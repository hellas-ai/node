use super::metrics::ShardMetrics;
use super::protocol::{
    BlockKey, CodingImpl, ShardMessage, WireShardMessage, ZodaCheckedShard, ZodaCheckingData,
    ZodaCommitment, ZodaReShard, ZodaShard, hash_encoded,
};
use super::recovery::{
    ReadyToCheckTask, RecoveryInput, RecoveryLimits, RecoveryMachine, RecoveryOutput,
};
use crate::trace::Traced;
use bytes::Bytes;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_parallel::Strategy;
use commonware_runtime::{Metrics, Spawner};
use futures::channel::mpsc;
use hellas_types::PublicKey;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex};
use tracing::{Span, info, info_span, warn};

// ---------------------------------------------------------------------------
// Public effect type
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) enum ShardEffect {
    Broadcast(Box<ShardMessage>),
    Recovered { key: BlockKey, contents: Bytes },
    Failed { key: BlockKey },
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct IncomingReShare {
    key: BlockKey,
    commitment: ZodaCommitment,
    shard_index: u16,
    reshard: <CodingImpl as CodingScheme>::ReShard,
}

// ---------------------------------------------------------------------------
// Coding task types (replaces scheduler module)
// ---------------------------------------------------------------------------

enum CodingTaskKind {
    Reshard {
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        shard: ZodaShard,
    },
    Check {
        commitment: ZodaCommitment,
        checking_data: ZodaCheckingData,
        shard_index: u16,
        shard_hash: Digest,
        reshard: ZodaReShard,
    },
}

struct CodingTask {
    key: BlockKey,
    span: Span,
    kind: CodingTaskKind,
}

// Order by BlockKey so BinaryHeap (max-heap) processes newest views first.
impl Eq for CodingTask {}
impl PartialEq for CodingTask {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl PartialOrd for CodingTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for CodingTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

enum CodingResult {
    ReshardDone {
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<(ZodaCheckingData, ZodaCheckedShard, ZodaReShard), ()>,
    },
    CheckDone {
        key: BlockKey,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<ZodaCheckedShard, ()>,
    },
}

// ---------------------------------------------------------------------------
// Shared priority queue — workers pull highest-priority tasks
// ---------------------------------------------------------------------------

struct SharedQueue {
    inner: Mutex<BinaryHeap<CodingTask>>,
    not_empty: Condvar,
    closed: AtomicBool,
}

impl SharedQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(BinaryHeap::new()),
            not_empty: Condvar::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn push(&self, task: CodingTask) {
        let mut inner = self.inner.lock().unwrap();
        inner.push(task);
        self.not_empty.notify_one();
    }

    /// Block until a task is available or the queue is closed.
    fn pop(&self) -> Option<CodingTask> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if self.closed.load(AtomicOrdering::Acquire) {
                return None;
            }
            if let Some(task) = inner.pop() {
                return Some(task);
            }
            inner = self.not_empty.wait(inner).unwrap();
        }
    }

    fn close(&self) {
        self.closed.store(true, AtomicOrdering::Release);
        self.not_empty.notify_all();
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Task execution (runs on worker threads)
// ---------------------------------------------------------------------------

fn execute_coding_task(config: CodingConfig, task: CodingTask) -> Traced<CodingResult> {
    let CodingTask { key, span, kind } = task;
    let result = {
        let _entered = span.enter();
        match kind {
            CodingTaskKind::Reshard {
                commitment,
                shard_index,
                shard_hash,
                shard,
            } => {
                let result = CodingImpl::reshard(&config, &commitment, shard_index, shard)
                    .map_err(|err| {
                        warn!(
                            digest = ?key.digest,
                            round = ?key.round,
                            shard_index,
                            ?err,
                            "reshard failed"
                        );
                    });
                CodingResult::ReshardDone {
                    key,
                    commitment,
                    shard_index,
                    shard_hash,
                    result,
                }
            }
            CodingTaskKind::Check {
                commitment,
                checking_data,
                shard_index,
                shard_hash,
                reshard,
            } => {
                let result = CodingImpl::check(
                    &config,
                    &commitment,
                    &checking_data,
                    shard_index,
                    reshard,
                )
                .map_err(|err| {
                    warn!(
                        digest = ?key.digest,
                        round = ?key.round,
                        shard_index,
                        ?err,
                        "check failed"
                    );
                });
                CodingResult::CheckDone {
                    key,
                    shard_index,
                    shard_hash,
                    result,
                }
            }
        }
    };
    Traced::with_span(result, span)
}

fn spawn_coding_workers(
    num_workers: usize,
    queue: Arc<SharedQueue>,
    config: CodingConfig,
    event_tx: mpsc::UnboundedSender<Traced<CodingResult>>,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..num_workers)
        .map(|i| {
            let queue = queue.clone();
            let event_tx = event_tx.clone();
            std::thread::Builder::new()
                .name(format!("coding-worker-{i}"))
                .spawn(move || {
                    while let Some(task) = queue.pop() {
                        let traced_result = execute_coding_task(config, task);
                        if event_tx.unbounded_send(traced_result).is_err() {
                            break;
                        }
                    }
                })
                .expect("failed to spawn coding worker thread")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// ShardRecoverer
// ---------------------------------------------------------------------------

pub(crate) struct ShardRecoverer<S: Strategy> {
    me: PublicKey,
    my_index: u16,
    coding_config: CodingConfig,
    strategy: S,
    machine: RecoveryMachine,
    metrics: ShardMetrics,
    queue: Arc<SharedQueue>,
    coding_event_rx: mpsc::UnboundedReceiver<Traced<CodingResult>>,
    _workers: Vec<std::thread::JoinHandle<()>>,
}

impl<S: Strategy> Drop for ShardRecoverer<S> {
    fn drop(&mut self) {
        self.queue.close();
    }
}

impl<S: Strategy> ShardRecoverer<S> {
    const MAX_RECOVERY_ENTRIES: usize = 8192;
    const MAX_BUFFERED_RESHARDS: usize = 128;
    const MAX_PRE_LEADER_MESSAGES: usize = 128;
    const MAX_PRE_LEADER_KEYS: usize = 256;
    const MAX_KNOWN_KEYS: usize = 4096;

    pub(crate) fn new(
        me: &PublicKey,
        my_index: u16,
        coding_config: CodingConfig,
        strategy: S,
        context: &(impl Spawner + Metrics + Clone),
    ) -> Self {
        let metrics = ShardMetrics::register(&context.with_label("shard"));
        let queue = Arc::new(SharedQueue::new());
        let (event_tx, coding_event_rx) = mpsc::unbounded();
        let num_workers = strategy.parallelism_hint();
        let workers =
            spawn_coding_workers(num_workers, queue.clone(), coding_config, event_tx);
        info!(num_workers, "coding workers started (streaming priority queue)");
        Self {
            me: me.clone(),
            my_index,
            coding_config,
            strategy,
            machine: RecoveryMachine::new(RecoveryLimits {
                max_known_keys: Self::MAX_KNOWN_KEYS,
                max_recovery_entries: Self::MAX_RECOVERY_ENTRIES,
                max_buffered_reshards: Self::MAX_BUFFERED_RESHARDS,
                max_pre_leader_messages: Self::MAX_PRE_LEADER_MESSAGES,
                max_pre_leader_keys: Self::MAX_PRE_LEADER_KEYS,
            }),
            metrics,
            queue,
            coding_event_rx,
            _workers: workers,
        }
    }

    pub(crate) fn shutdown(&mut self) {
        self.queue.close();
    }

    pub(crate) const fn me(&self) -> &PublicKey {
        &self.me
    }

    pub(crate) const fn coding_config(&self) -> &CodingConfig {
        &self.coding_config
    }

    // ---- Drain coding results (non-blocking) ----

    pub(crate) fn drain_coding_events(&mut self) -> VecDeque<ShardEffect> {
        let mut effects = VecDeque::new();
        let mut drained = 0u32;
        while let Ok(Some(traced)) = self.coding_event_rx.try_next() {
            let (result, parent_span) = traced.into_parts();
            // Re-enter the caller's span so that downstream work
            // (apply_reshard_result, try_recover, etc.) appears as children
            // of the original handle_message span.  This is synchronous code,
            // so .enter() is safe.
            let _entered = parent_span.enter();
            self.apply_coding_result(result, &mut effects);
            drained += 1;
        }
        if drained > 0 {
            self.metrics
                .scheduler_queue_depth
                .set(self.queue.len() as i64);
            info!(
                drained,
                recoveries = effects.iter().filter(|e| matches!(e, ShardEffect::Recovered { .. })).count(),
                "drained coding events"
            );
        }
        effects
    }

    fn apply_coding_result(
        &mut self,
        result: CodingResult,
        effects: &mut VecDeque<ShardEffect>,
    ) {
        self.metrics.coding_tasks_completed_total.inc();
        match result {
            CodingResult::ReshardDone {
                key,
                commitment,
                shard_index,
                shard_hash,
                result,
            } => {
                self.apply_reshard_result(
                    key, commitment, shard_index, shard_hash, result, effects,
                );
            }
            CodingResult::CheckDone {
                key,
                shard_index,
                shard_hash,
                result,
            } => {
                self.apply_check_result(key, shard_index, shard_hash, result, effects);
            }
        }
    }

    fn apply_reshard_result(
        &mut self,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<
            (
                <CodingImpl as CodingScheme>::CheckingData,
                <CodingImpl as CodingScheme>::CheckedShard,
                <CodingImpl as CodingScheme>::ReShard,
            ),
            (),
        >,
        effects: &mut VecDeque<ShardEffect>,
    ) {
        let _span = info_span!(
            "shard.apply_reshard_result",
            payload = ?key.digest,
            round = ?key.round,
            shard_index,
        )
        .entered();
        let Ok((checking_data, checked_shard, reshard)) = result else {
            // Crypto failure already logged by the worker.
            return;
        };

        for output in self.machine.step(RecoveryInput::ApplyInitialValidated {
            key,
            commitment,
            shard_index,
            shard_hash,
            checking_data,
            checked_shard,
        }) {
            match output {
                RecoveryOutput::ReadyToCheck(task) => self.dispatch_check(task),
                other => self.push_machine_effect(other, key, effects),
            }
        }
        self.sync_machine_gauges();

        effects.push_back(ShardEffect::Broadcast(Box::new(ShardMessage::reshare(
            &self.me,
            key,
            commitment,
            self.my_index,
            reshard,
        ))));
        if let Some(effect) = self.try_recover(key) {
            effects.push_back(effect);
        }
    }

    fn apply_check_result(
        &mut self,
        key: BlockKey,
        shard_index: u16,
        shard_hash: Digest,
        result: Result<<CodingImpl as CodingScheme>::CheckedShard, ()>,
        effects: &mut VecDeque<ShardEffect>,
    ) {
        let _span = info_span!(
            "shard.apply_check_result",
            payload = ?key.digest,
            round = ?key.round,
            shard_index,
        )
        .entered();
        let Ok(checked_shard) = result else {
            // Crypto failure already logged by the worker.
            return;
        };

        for output in self.machine.step(RecoveryInput::ApplyCheckedReShare {
            key,
            shard_index,
            shard_hash,
            checked_shard,
        }) {
            self.push_machine_effect(output, key, effects);
        }
        self.sync_machine_gauges();
        if let Some(effect) = self.try_recover(key) {
            effects.push_back(effect);
        }
    }

    // ---- Dispatch tasks to coding worker pool ----

    fn dispatch_reshard(
        &self,
        key: BlockKey,
        commitment: ZodaCommitment,
        shard_index: u16,
        shard_hash: Digest,
        shard: <CodingImpl as CodingScheme>::Shard,
    ) {
        self.queue.push(CodingTask {
            key,
            span: Span::current(),
            kind: CodingTaskKind::Reshard {
                commitment,
                shard_index,
                shard_hash,
                shard,
            },
        });
        self.metrics.coding_tasks_dispatched_total.inc();
        self.metrics
            .scheduler_queue_depth
            .set(self.queue.len() as i64);
    }

    fn dispatch_check(&self, task: ReadyToCheckTask) {
        self.queue.push(CodingTask {
            key: task.key,
            span: Span::current(),
            kind: CodingTaskKind::Check {
                commitment: task.commitment,
                checking_data: task.checking_data,
                shard_index: task.shard_index,
                shard_hash: task.shard_hash,
                reshard: task.reshard,
            },
        });
        self.metrics.coding_tasks_dispatched_total.inc();
        self.metrics
            .scheduler_queue_depth
            .set(self.queue.len() as i64);
    }

    // ---- Message handling ----

    pub(crate) fn note_known_key(
        &mut self,
        key: BlockKey,
        leader: &PublicKey,
    ) -> (Vec<ShardMessage>, VecDeque<ShardEffect>) {
        let mut drained = Vec::new();
        let mut effects = VecDeque::new();
        for output in self.machine.step(RecoveryInput::NoteKnownKey {
            key,
            leader: leader.clone(),
        }) {
            match output {
                RecoveryOutput::DrainedPreLeader(messages) => drained.extend(messages),
                RecoveryOutput::KnownKeyEvicted { key: evicted } => {
                    self.metrics.recovery_evictions_total.inc();
                    effects.push_back(ShardEffect::Failed { key: evicted });
                }
                _ => {}
            }
        }
        self.sync_machine_gauges();
        (drained, effects)
    }

    pub(crate) fn handle_message<F>(
        &mut self,
        message: ShardMessage,
        seen: &HashMap<Digest, Bytes>,
        validator_index: F,
    ) -> VecDeque<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let Some(key) = message.key() else {
            return VecDeque::new();
        };
        if seen.contains_key(&key.digest) {
            return VecDeque::new();
        }
        let span = info_span!(
            "shard.handle_message",
            payload = ?key.digest,
            round = ?key.round,
        );
        // Derive a deterministic trace ID from the block digest so that all
        // validators processing shards for the same payload share a single
        // trace, with per-node subtrees rooted at unique span IDs.
        let trace_id: [u8; 16] = key.digest.0[..16]
            .try_into()
            .expect("digest has at least 16 bytes");
        let mut span_id_input = Vec::with_capacity(64);
        span_id_input.extend_from_slice(&key.digest.0);
        span_id_input.extend_from_slice(commonware_codec::Encode::encode(&self.me).as_ref());
        let span_id_hash = Sha256::hash(&span_id_input);
        let span_id: [u8; 8] = span_id_hash.0[..8]
            .try_into()
            .expect("hash has at least 8 bytes");
        crate::trace::set_block_trace_context(&span, trace_id, span_id);
        let _span = span.entered();

        let mut effects = VecDeque::new();
        let outputs = self.machine.step(RecoveryInput::IngressMessage {
            message: Box::new(message),
        });
        self.sync_machine_gauges();

        for output in outputs {
            match output {
                RecoveryOutput::IngressReady {
                    message,
                    expected_leader,
                } => {
                    let ShardMessage { sender, body } = *message;
                    match body {
                        WireShardMessage::Initial {
                            key,
                            commitment,
                            shard,
                            shard_index,
                        } => effects.extend(self.handle_initial(
                            key,
                            sender,
                            expected_leader,
                            commitment,
                            shard,
                            shard_index,
                        )),
                        WireShardMessage::ReShare {
                            key,
                            commitment,
                            shard_index,
                            reshard,
                        } => effects.extend(self.handle_reshare(
                            sender,
                            expected_leader,
                            IncomingReShare {
                                key,
                                commitment,
                                shard_index,
                                reshard,
                            },
                            &validator_index,
                        )),
                        WireShardMessage::FetchPayload { .. }
                        | WireShardMessage::PayloadResponse { .. } => {}
                    }
                }
                RecoveryOutput::BufferedPreLeader => {
                    info!(payload = ?key.digest, "shard message buffered pre-leader");
                }
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }
        effects
    }

    fn handle_initial(
        &mut self,
        key: BlockKey,
        sender: PublicKey,
        expected_leader: PublicKey,
        commitment: ZodaCommitment,
        shard: <CodingImpl as CodingScheme>::Shard,
        shard_index: u16,
    ) -> VecDeque<ShardEffect> {
        if sender != expected_leader || shard_index != self.my_index {
            info!(
                payload = ?key.digest,
                shard_index,
                my_index = self.my_index,
                sender_is_leader = (sender == expected_leader),
                "handle_initial: rejecting initial shard"
            );
            return VecDeque::new();
        }
        info!(
            payload = ?key.digest,
            shard_index,
            "handle_initial: accepted initial shard, dispatching reshard"
        );

        let shard_hash = hash_encoded(&shard);
        let mut effects = VecDeque::new();
        let mut accepted = false;
        for output in self.machine.step(RecoveryInput::ObserveInitial {
            key,
            sender: sender.clone(),
            commitment,
            shard_index,
            shard_hash,
            leader: expected_leader,
        }) {
            match output {
                RecoveryOutput::InitialAccepted => accepted = true,
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }
        self.sync_machine_gauges();
        if !accepted {
            return effects;
        }

        // Dispatch reshard to a coding worker thread.
        // Results arrive via drain_coding_events → apply_reshard_result,
        // which handles ApplyInitialValidated, broadcast, and try_recover.
        self.dispatch_reshard(key, commitment, shard_index, shard_hash, shard);
        effects
    }

    fn handle_reshare<F>(
        &mut self,
        sender: PublicKey,
        expected_leader: PublicKey,
        incoming: IncomingReShare,
        validator_index: &F,
    ) -> VecDeque<ShardEffect>
    where
        F: Fn(&PublicKey) -> Option<u16>,
    {
        let IncomingReShare {
            key,
            commitment,
            shard_index,
            reshard,
        } = incoming;

        let Some(expected_index) = validator_index(&sender) else {
            return VecDeque::new();
        };
        if expected_index != shard_index {
            return VecDeque::new();
        }

        let shard_hash = hash_encoded(&reshard);
        let mut effects = VecDeque::new();
        for output in self.machine.step(RecoveryInput::ObserveReShare {
            key,
            sender: sender.clone(),
            commitment,
            shard_index,
            shard_hash,
            reshard,
            leader: expected_leader,
        }) {
            match output {
                RecoveryOutput::ReadyToCheck(task) => self.dispatch_check(task),
                RecoveryOutput::ReShareBuffered => {}
                other => self.push_machine_effect(other, key, &mut effects),
            }
        }
        self.sync_machine_gauges();

        effects
    }

    fn try_recover(&mut self, key: BlockKey) -> Option<ShardEffect> {
        let _span = info_span!(
            "shard.try_recover",
            payload = ?key.digest,
            round = ?key.round,
        )
        .entered();
        let mut decode_candidate = None;
        for output in self.machine.step(RecoveryInput::TryTakeDecode {
            key,
            minimum_shards: self.coding_config.minimum_shards,
        }) {
            match output {
                RecoveryOutput::ReadyToDecode(candidate) => decode_candidate = Some(candidate),
                other => {
                    if let Some(effect) = self.machine_output_to_effect(other, key) {
                        return Some(effect);
                    }
                }
            }
        }
        self.sync_machine_gauges();
        let decode_candidate = decode_candidate?;

        let reconstructed = match CodingImpl::decode(
            &self.coding_config,
            &decode_candidate.commitment,
            decode_candidate.checking_data,
            decode_candidate.checked_shards.as_slice(),
            &self.strategy,
        ) {
            Ok(decoded) => decoded,
            Err(err) => {
                warn!(
                    digest = ?key.digest,
                    round = ?key.round,
                    ?err,
                    "shard decode failed"
                );
                self.metrics.recovery_failed_total.inc();
                return Some(ShardEffect::Failed { key });
            }
        };

        if Sha256::hash(reconstructed.as_slice()) != key.digest {
            warn!(
                digest = ?key.digest,
                round = ?key.round,
                "decoded payload digest mismatch"
            );
            self.metrics.recovery_failed_total.inc();
            return Some(ShardEffect::Failed { key });
        }

        self.metrics.recovery_success_total.inc();
        Some(ShardEffect::Recovered {
            key,
            contents: Bytes::from(reconstructed),
        })
    }

    fn push_machine_effect(
        &self,
        output: RecoveryOutput,
        incoming: BlockKey,
        effects: &mut VecDeque<ShardEffect>,
    ) {
        if let Some(effect) = self.machine_output_to_effect(output, incoming) {
            effects.push_back(effect);
        }
    }

    /// Update recovery machine gauges. Called after machine.step() calls that
    /// may add or remove entries.
    fn sync_machine_gauges(&self) {
        self.metrics.active_recoveries.set(self.machine.active_count() as i64);
        self.metrics.known_keys.set(self.machine.known_keys_count() as i64);
        self.metrics.pre_leader_keys.set(self.machine.pre_leader_keys_count() as i64);
    }

    fn machine_output_to_effect(
        &self,
        output: RecoveryOutput,
        incoming: BlockKey,
    ) -> Option<ShardEffect> {
        match output {
            RecoveryOutput::Evicted { key } => {
                warn!(
                    evicted = ?key,
                    incoming = ?incoming,
                    max_recovery_entries = Self::MAX_RECOVERY_ENTRIES,
                    "evicting oldest recovery entry to admit new recovery"
                );
                self.metrics.recovery_evictions_total.inc();
                Some(ShardEffect::Failed { key })
            }
            RecoveryOutput::KnownKeyEvicted { key } => {
                // Handled directly in note_known_key; should not reach here.
                warn!(evicted = ?key, "unexpected KnownKeyEvicted in machine_output_to_effect");
                None
            }
            RecoveryOutput::CommitmentMismatch {
                key,
                shard_index,
                sender,
                source,
            } => {
                if source == "reshare" {
                    warn!(
                        digest = ?key.digest,
                        shard_index,
                        ?sender,
                        "commitment mismatch for reshard"
                    );
                } else {
                    warn!(digest = ?key.digest, "commitment mismatch for initial shard");
                }
                None
            }
            RecoveryOutput::Equivocation {
                key,
                shard_index,
                sender,
                source,
            } => {
                warn!(
                    digest = ?key.digest,
                    shard_index,
                    ?sender,
                    source,
                    "equivocation detected for shard"
                );
                None
            }
            RecoveryOutput::DuplicateShard
            | RecoveryOutput::BufferedPreLeader
            | RecoveryOutput::DrainedPreLeader(_)
            | RecoveryOutput::IngressReady { .. }
            | RecoveryOutput::InitialAccepted
            | RecoveryOutput::ReShareBuffered
            | RecoveryOutput::ReadyToCheck(_)
            | RecoveryOutput::ReadyToDecode(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::protocol::coding_config;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{Signer, ed25519};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Spawner, deterministic};
    use std::time::Duration;

    struct BlockArtifacts {
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<<CodingImpl as CodingScheme>::Shard>,
        reshares: Vec<<CodingImpl as CodingScheme>::ReShard>,
    }

    struct Fixture {
        validators: Vec<PublicKey>,
        index_by_validator: HashMap<PublicKey, u16>,
        leader: PublicKey,
        my_index: u16,
        recoverer: ShardRecoverer<commonware_parallel::Rayon>,
    }

    impl Fixture {
        fn new(context: &(impl Spawner + Metrics + Clone)) -> Self {
            let mut validators: Vec<_> = (0u64..6u64)
                .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
                .collect();
            validators.sort();
            let my_index = 1u16;
            let me = validators[usize::from(my_index)].clone();
            let leader = validators[0].clone();
            let strategy = crate::coding_strategy();
            let recoverer = ShardRecoverer::new(&me, my_index, coding_config(6), strategy, context);
            let mut index_by_validator = HashMap::new();
            for (idx, validator) in validators.iter().enumerate() {
                let validator_index = u16::try_from(idx).expect("index should fit into u16");
                index_by_validator.insert(validator.clone(), validator_index);
            }
            Self {
                validators,
                index_by_validator,
                leader,
                my_index,
                recoverer,
            }
        }

        fn handle_message(
            &mut self,
            message: ShardMessage,
            seen: &HashMap<Digest, Bytes>,
        ) -> VecDeque<ShardEffect> {
            let index_by_validator = &self.index_by_validator;
            self.recoverer
                .handle_message(message, seen, |pk| index_by_validator.get(pk).copied())
        }

        fn note_known_key(&mut self, key: BlockKey) -> (Vec<ShardMessage>, VecDeque<ShardEffect>) {
            self.recoverer.note_known_key(key, &self.leader)
        }

        fn make_artifacts(&self, view: u64, payload: &[u8]) -> BlockArtifacts {
            let key = BlockKey::new(
                Round::new(Epoch::new(1), View::new(view)),
                Sha256::hash(payload),
            );
            let (commitment, shards) =
                CodingImpl::encode(self.recoverer.coding_config(), payload, &Sequential)
                    .expect("encode should succeed");
            let mut reshares = Vec::with_capacity(shards.len());
            for (idx, shard) in shards.iter().cloned().enumerate() {
                let shard_index = u16::try_from(idx).expect("index should fit into u16");
                let (_, _, reshard) = CodingImpl::reshard(
                    self.recoverer.coding_config(),
                    &commitment,
                    shard_index,
                    shard,
                )
                .expect("reshard should succeed");
                reshares.push(reshard);
            }
            BlockArtifacts {
                key,
                commitment,
                shards,
                reshares,
            }
        }
    }

    #[test_log::test]
    fn pre_leader_reshare_is_drained_after_note_known_key() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let mut fixture = Fixture::new(&context);
            let artifacts = fixture.make_artifacts(1, b"buffer-then-recover");
            let sender = fixture.validators[2].clone();
            let shard_index = 2u16;
            let reshare = artifacts.reshares[usize::from(shard_index)].clone();

            let seen = HashMap::<Digest, Bytes>::new();
            let buffered = fixture.handle_message(
                ShardMessage::reshare(
                    &sender,
                    artifacts.key,
                    artifacts.commitment,
                    shard_index,
                    reshare,
                ),
                &seen,
            );
            assert!(buffered.is_empty());
            assert!(fixture.recoverer.machine.inspect(
                |_recovery, _known_leaders, pre_leader_buffer| {
                    pre_leader_buffer.contains_key(&artifacts.key)
                }
            ));

            let (drained, _eviction_effects) = fixture.note_known_key(artifacts.key);
            assert_eq!(drained.len(), 1);

            for msg in drained {
                let effects = fixture.handle_message(msg, &seen);
                assert!(effects.is_empty());
            }
            assert!(!fixture.recoverer.machine.inspect(
                |_recovery, _known_leaders, pre_leader_buffer| {
                    pre_leader_buffer.contains_key(&artifacts.key)
                }
            ));
            let buffered_reshards_len = fixture.recoverer.machine.inspect(
                |recovery, _known_leaders, _pre_leader_buffer| {
                    recovery
                        .get(&artifacts.key)
                        .map(|recovery| recovery.buffered_reshards_len())
                },
            );
            assert_eq!(
                buffered_reshards_len,
                Some(1),
                "drained reshare should start recovery state"
            );
        });
    }

    #[test_log::test]
    fn wrong_sender_initial_does_not_poison_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let mut fixture = Fixture::new(&context);
            let good = fixture.make_artifacts(2, b"good-payload");
            let bad = fixture.make_artifacts(2, b"bad-payload");
            let attacker = fixture.validators[3].clone();

            let _ = fixture.note_known_key(good.key);
            let seen = HashMap::<Digest, Bytes>::new();

            let malicious = fixture.handle_message(
                ShardMessage::initial(
                    &attacker,
                    good.key,
                    bad.commitment,
                    bad.shards[usize::from(fixture.my_index)].clone(),
                    fixture.my_index,
                ),
                &seen,
            );
            assert!(malicious.is_empty());
            assert!(!fixture.recoverer.machine.inspect(
                |recovery, _known_leaders, _pre_leader_buffer| { recovery.contains_key(&good.key) }
            ));

            let _ = fixture.handle_message(
                ShardMessage::initial(
                    &fixture.leader,
                    good.key,
                    good.commitment,
                    good.shards[usize::from(fixture.my_index)].clone(),
                    fixture.my_index,
                ),
                &seen,
            );
            let commitment = fixture.recoverer.machine.inspect(
                |recovery, _known_leaders, _pre_leader_buffer| {
                    recovery
                        .get(&good.key)
                        .map(|recovery| recovery.commitment())
                },
            );
            let Some(commitment) = commitment else {
                panic!("leader initial should create recovery state");
            };
            assert_eq!(commitment, good.commitment);
            assert_ne!(commitment, bad.commitment);
        });
    }
}
