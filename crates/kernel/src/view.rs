//! Allocation-free state snapshots for models and refinement checks.
//!
//! Abstract counterpart: the live `coins` / `edges` / `liveCoins` /
//! `liveEdges` projections in `models/l1.qnt`. ITF replay (`tests/itf.rs`)
//! reads each abstract step and asserts the kernel's [`View`] matches; the
//! model's `valueConserved`, `noNegativeValue`, and shape rules
//! (`models/rules/invariants.qnt`) are checked against this same view.
//!
//! Registry chunks are the third live object kind and appear here for the
//! same reason coins and edges do: state the harness cannot see is state
//! whose corruption no invariant can catch. The Quint model does not yet
//! own them — `models/registry.md` records precisely what that costs —
//! so the invariant a replay can assert today is that the transitions it
//! replays write no registry state at all.

use crate::{
    consts::ID_LENGTH,
    network::NetworkId,
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
    registry::{RegistryChunk, RegistryChunkId, RegistryNamespace, RegistryRecordTag},
};

/// Abstract live-state view over bounded coin, edge, and registry sets.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct View<const C: usize, const E: usize, const R: usize = 0> {
    coins: [Option<(CoinId, Coin)>; C],
    edges: [Option<(EdgeId, Edge)>; E],
    registry: [Option<(RegistryChunkId, RegistryChunk)>; R],
}

impl<const C: usize, const E: usize> View<C, E> {
    /// Creates a compact view from bounded live coin and edge arrays.
    #[must_use]
    pub fn new(coins: [Option<(CoinId, Coin)>; C], edges: [Option<(EdgeId, Edge)>; E]) -> Self {
        Self::with_registry(coins, edges, [])
    }
}

impl<const C: usize, const E: usize, const R: usize> View<C, E, R> {
    /// Creates a compact view from bounded live-object arrays.
    #[must_use]
    pub fn with_registry(
        coins: [Option<(CoinId, Coin)>; C],
        edges: [Option<(EdgeId, Edge)>; E],
        registry: [Option<(RegistryChunkId, RegistryChunk)>; R],
    ) -> Self {
        Self {
            coins: pack_sorted(coins),
            edges: pack_sorted(edges),
            registry: pack_sorted(registry),
        }
    }

    /// Iterates over live coins.
    pub fn coins(&self) -> impl Iterator<Item = (CoinId, Coin)> + '_ {
        self.coins.iter().copied().flatten()
    }

    /// Iterates over live edges.
    pub fn edges(&self) -> impl Iterator<Item = (EdgeId, Edge)> + '_ {
        self.edges.iter().copied().flatten()
    }

    /// Iterates over live registry chunks.
    pub fn registry_chunks(&self) -> impl Iterator<Item = (RegistryChunkId, RegistryChunk)> + '_ {
        self.registry.iter().copied().flatten()
    }

    /// Returns the live coin stored under `id`, if any.
    #[must_use]
    pub fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins()
            .find_map(|(coin_id, coin)| (coin_id == id).then_some(coin))
    }

    /// Returns the live edge stored under `id`, if any.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges()
            .find_map(|(edge_id, edge)| (edge_id == id).then_some(edge))
    }

    /// Returns the live registry chunk stored under `id`, if any.
    #[must_use]
    pub fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry_chunks()
            .find_map(|(chunk_id, chunk)| (chunk_id == id).then_some(chunk))
    }

    /// Returns the number of live coins.
    #[must_use]
    pub fn coin_len(&self) -> usize {
        self.coins().count()
    }

    /// Returns the number of live edges.
    #[must_use]
    pub fn edge_len(&self) -> usize {
        self.edges().count()
    }

    /// Returns the number of live registry chunks.
    #[must_use]
    pub fn registry_len(&self) -> usize {
        self.registry_chunks().count()
    }

    /// Reassembles the registry value stored under `key` in `namespace`
    /// into `buf`, returning its record kind and bytes.
    ///
    /// This is where the cross-chunk rules are decided. A chunk's decoder
    /// proves the chunk is the unique canonical encoding of the slice it
    /// claims to be, but "every index present, each in its own slot,
    /// nothing past the end, one record kind throughout" needs every
    /// sibling — which is exactly what a view holds. Any violation reads
    /// as absent rather than as a shorter or different value, so a
    /// caller can never splice a corrupted record back together.
    ///
    /// Returns `None` when the value is absent, incomplete, internally
    /// inconsistent, or longer than `buf`.
    #[must_use]
    pub fn registry_value<'buf>(
        &self,
        network: NetworkId,
        namespace: RegistryNamespace,
        key: [u8; ID_LENGTH],
        buf: &'buf mut [u8],
    ) -> Option<(RegistryRecordTag, &'buf [u8])> {
        let slot = |index: u8| RegistryChunkId::derive(network, namespace, key, index);

        // Any one chunk names the whole value's length and chunk count,
        // so the first slot decides how much there is to collect.
        let head = self.registry_chunk(slot(0))?;
        let record_tag = head.record_tag();
        let count = head.chunk_count();
        let value_len = usize::from(head.value_len());
        let mut written = 0_usize;

        for index in 0..count {
            let chunk = self.registry_chunk(slot(index))?;
            // The index comparison is what separates a value from a
            // permutation of itself, and the length comparison what
            // separates it from a same-count neighbour: two values one
            // byte apart in length can agree on every other field and
            // still sum to the same total. `chunk_count` is derived
            // from `value_len` in every constructor, so comparing it
            // adds nothing the length comparison does not already
            // decide; it is here because a reader should not have to
            // know that to trust the loop.
            if chunk.namespace() != namespace
                || chunk.record_tag() != record_tag
                || chunk.chunk_index() != index
                || chunk.chunk_count() != count
                || chunk.value_len() != head.value_len()
            {
                return None;
            }
            let data = chunk.data();
            let end = written.checked_add(data.len())?;
            buf.get_mut(written..end)?.copy_from_slice(data);
            written = end;
        }

        // Unreachable while every chunk's data length is fixed by its
        // index and its value length, which the chunk's own encoding
        // guarantees. Kept because this function is the one that hands
        // bytes to a caller, and a caller must not be handed a prefix.
        if written != value_len {
            return None;
        }
        // A value that shrank must not leave a stale tail behind: the
        // slot one past the end has to be empty, or a later reader with
        // a longer head chunk would splice the orphan back in.
        if count < u8::MAX && self.registry_chunk(slot(count)).is_some() {
            return None;
        }

        buf.get(..written).map(|value| (record_tag, value))
    }
}

/// Compacts live entries to the front and sorts them by identifier.
fn pack_sorted<K: Ord + Copy, V: Copy, const N: usize>(
    items: [Option<(K, V)>; N],
) -> [Option<(K, V)>; N] {
    let mut packed = [None; N];
    let mut len = 0;
    for (slot, item) in packed.iter_mut().zip(items.into_iter().flatten()) {
        *slot = Some(item);
        len += 1;
    }
    if let Some(live) = packed.get_mut(..len) {
        live.sort_unstable_by(|left, right| match (left, right) {
            (Some((left_id, _)), Some((right_id, _))) => left_id.cmp(right_id),
            // The packed prefix holds only `Some` entries.
            _ => core::cmp::Ordering::Equal,
        });
    }
    packed
}

/// Store extension for producing bounded abstract state views.
///
/// Each store picks its canonical `View` shape via the associated type so
/// callers can write `state.view()` without turbofish.
pub trait Snapshot {
    /// Bounded view shape produced by this store.
    type View;

    /// Returns the live-state view for this store.
    #[must_use]
    fn view(&self) -> Self::View;
}
