use crate::backend::ExecBackend;
use catgrad_llm::{BoundProgram, Snapshot};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_PREFIX_CACHE_MAX_BYTES: usize = 1 << 30;

#[derive(Clone)]
pub(crate) struct CachedProgram {
    bound_program: Arc<BoundProgram<ExecBackend>>,
    empty_snapshot: Arc<Snapshot<ExecBackend>>,
    prefix_cache: Arc<Mutex<PrefixCache>>,
}

#[derive(Clone)]
pub(crate) struct PrefixMatch {
    pub prefix_len: usize,
    pub prefix_hash: PrefixHash,
    pub next_token: u32,
    pub snapshot: Arc<Snapshot<ExecBackend>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PrefixHash([u8; 32]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PrefixState {
    len: usize,
    hash: PrefixHash,
}

#[derive(Clone)]
struct PrefixEntry {
    snapshot: Arc<Snapshot<ExecBackend>>,
    next_token: u32,
    bytes: usize,
    last_touch: u64,
}

struct PrefixCache {
    entries: HashMap<(usize, PrefixHash), PrefixEntry>,
    max_bytes: usize,
    total_bytes: usize,
    touch_clock: u64,
}

impl CachedProgram {
    pub(crate) fn new(bound_program: Arc<BoundProgram<ExecBackend>>) -> Self {
        debug!(
            program_id = %bound_program.id(),
            state_tensors = bound_program.program().empty_state_type.len(),
            max_bytes = DEFAULT_PREFIX_CACHE_MAX_BYTES,
            "initialized prefix cache"
        );
        Self {
            empty_snapshot: Arc::new(bound_program.empty_snapshot()),
            prefix_cache: Arc::new(Mutex::new(PrefixCache::new(DEFAULT_PREFIX_CACHE_MAX_BYTES))),
            bound_program,
        }
    }

    pub(crate) fn bound_program(&self) -> &BoundProgram<ExecBackend> {
        self.bound_program.as_ref()
    }

    pub(crate) fn empty_snapshot(&self) -> Arc<Snapshot<ExecBackend>> {
        self.empty_snapshot.clone()
    }

    pub(crate) fn lookup_prefix(&self, tokens: &[u32]) -> Option<PrefixMatch> {
        let mut cache = self
            .prefix_cache
            .lock()
            .expect("prefix cache mutex poisoned");
        let matched = cache.lookup_deepest(tokens);
        debug!(
            program_id = %self.bound_program.id(),
            prompt_tokens = tokens.len(),
            matched_prefix_tokens = matched.as_ref().map_or(0, |entry| entry.prefix_len),
            cache_entries = cache.entry_count(),
            cache_bytes = cache.total_bytes(),
            "prefix cache lookup"
        );
        matched
    }

    pub(crate) fn cache_prefix(
        &self,
        prefix_len: usize,
        prefix_hash: PrefixHash,
        next_token: u32,
        snapshot: Snapshot<ExecBackend>,
    ) {
        let snapshot_bytes = snapshot.logical_bytes();
        self.prefix_cache
            .lock()
            .expect("prefix cache mutex poisoned")
            .insert(
                self.bound_program.id(),
                prefix_len,
                prefix_hash,
                next_token,
                snapshot_bytes,
                Arc::new(snapshot),
            );
    }
}

impl PrefixHash {
    pub(crate) const fn seed() -> Self {
        Self([0; 32])
    }

    pub(crate) fn extend(self, token: u32) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        hasher.update(&token.to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

impl PrefixState {
    pub(crate) const fn seed() -> Self {
        Self {
            len: 0,
            hash: PrefixHash::seed(),
        }
    }

    pub(crate) const fn from_parts(len: usize, hash: PrefixHash) -> Self {
        Self { len, hash }
    }

    #[cfg(test)]
    pub(crate) fn from_tokens(tokens: &[u32]) -> Self {
        let mut state = Self::seed();
        state.extend_tokens(tokens);
        state
    }

    pub(crate) fn extend(&mut self, token: u32) {
        self.hash = self.hash.extend(token);
        self.len += 1;
    }

    pub(crate) fn extend_tokens(&mut self, tokens: &[u32]) {
        for &token in tokens {
            self.extend(token);
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn hash(&self) -> PrefixHash {
        self.hash
    }
}

impl PrefixCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_bytes,
            total_bytes: 0,
            touch_clock: 0,
        }
    }

    fn lookup_deepest(&mut self, tokens: &[u32]) -> Option<PrefixMatch> {
        let mut state = PrefixState::seed();
        let mut best = None;

        for &token in tokens {
            state.extend(token);
            let key = (state.len(), state.hash());
            let touch = self.next_touch();
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.last_touch = touch;
                best = Some(PrefixMatch {
                    prefix_len: state.len(),
                    prefix_hash: state.hash(),
                    next_token: entry.next_token,
                    snapshot: entry.snapshot.clone(),
                });
            }
        }

        best
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn insert(
        &mut self,
        program_id: &str,
        prefix_len: usize,
        prefix_hash: PrefixHash,
        next_token: u32,
        snapshot_bytes: usize,
        snapshot: Arc<Snapshot<ExecBackend>>,
    ) {
        if prefix_len == 0 || snapshot_bytes == 0 || snapshot_bytes > self.max_bytes {
            debug!(
                %program_id,
                prefix_len,
                snapshot_bytes,
                max_bytes = self.max_bytes,
                skip_zero_len = prefix_len == 0,
                skip_zero_size = snapshot_bytes == 0,
                skip_oversize = snapshot_bytes > self.max_bytes,
                "skipping prefix cache insert"
            );
            return;
        }

        let key = (prefix_len, prefix_hash);
        let touch = self.next_touch();
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_touch = touch;
            debug!(
                %program_id,
                prefix_len,
                cache_entries = self.entries.len(),
                cache_bytes = self.total_bytes,
                snapshot_bytes,
                "prefix cache insert hit existing entry"
            );
            return;
        }

        while self.total_bytes.saturating_add(snapshot_bytes) > self.max_bytes {
            let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_touch)
                .map(|(key, _)| *key)
            else {
                break;
            };
            if let Some(removed) = self.entries.remove(&lru_key) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
                debug!(
                    %program_id,
                    evicted_prefix_len = lru_key.0,
                    cache_entries = self.entries.len(),
                    cache_bytes = self.total_bytes,
                    "evicted prefix cache entry"
                );
            }
        }

        self.entries.insert(
            key,
            PrefixEntry {
                snapshot,
                next_token,
                bytes: snapshot_bytes,
                last_touch: touch,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(snapshot_bytes);
        debug!(
            %program_id,
            prefix_len,
            cache_entries = self.entries.len(),
            cache_bytes = self.total_bytes,
            snapshot_bytes,
            "inserted prefix cache entry"
        );
    }

    fn next_touch(&mut self) -> u64 {
        let touch = self.touch_clock;
        self.touch_clock = self.touch_clock.wrapping_add(1);
        touch
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixState;

    #[test]
    fn prefix_state_matches_incremental_hashing() {
        let tokens = [1, 2, 3, 4];
        let batch = PrefixState::from_tokens(&tokens);
        let mut incremental = PrefixState::seed();
        incremental.extend_tokens(&tokens);
        assert_eq!(batch.len(), incremental.len());
        assert_eq!(batch.hash(), incremental.hash());
    }
}
