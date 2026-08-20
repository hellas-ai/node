//! Consensus-only registry state, stored as fixed-size chunks.
//!
//! A registry value is a protocol record that consensus must agree on but
//! that no party owns: it is not a coin and not an edge, and nothing
//! outside the kernel spends it. Some of those records are larger than
//! the payload area the chain's stored object reserves, so a value is
//! split into fixed [`RegistryChunk`]s and each chunk gets its own
//! deterministically derived id in the same authenticated object
//! database. The database therefore keeps one authenticated state root
//! over coins, edges, and registry chunks alike — the alternative, a
//! second store beside it, would put consensus state outside the root
//! that consensus commits to.
//!
//! Splitting is what keeps the stored object at its current size. A
//! value's length is carried by each of its chunks rather than by a
//! separate header object, so a reader that holds any one chunk already
//! knows how many more to fetch and how many bytes to expect.
//!
//! # What a single chunk can prove about itself
//!
//! Every canonicality rule that depends on one chunk alone is enforced by
//! [`Decode`]: the version, the closed namespace and record tags, a
//! nonzero value length, a chunk count derived from that length, an index
//! inside that count, the exact data length for that index, and zero
//! bytes after it. A stored chunk that decodes is therefore the unique
//! encoding of the slice it claims to be.
//!
//! The rules that span chunks — no duplicate index, no missing index, and
//! one exact tagged record after reassembly — cannot be decided from one
//! chunk and are not checked here.
//!
//! # Who stores what here
//!
//! The substrate is shared and the record bodies are not. Two records
//! exist today, and each owns its own namespace, its own slot
//! derivation, and its own reassembly rules: the one-chunk
//! [`crate::PendingPaymentClose`] of a payment-close contest, in
//! [`crate::work`], and the two-chunk [`crate::BondLease`] a payment open
//! takes over a provider's stake, in [`crate::lease`]. Both are read back
//! through their own module rather than through a generic accessor here,
//! because the rule that a present-but-unreadable value is a fault rather
//! than absence is a property of the record, not of the chunk.
//!
//! Abstract counterpart: none yet. The Quint model in `models/` covers
//! coins and edges; registry state enters it with the transitions that
//! mutate it, not with the storage substrate. `models/registry.md` is the
//! authoritative list of what that gap costs and which Rust tests stand
//! in meanwhile.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        decode_fixed, encode_envelope, tag,
    },
    consts::{
        ID_LENGTH, MAX_REGISTRY_CHUNKS, MAX_REGISTRY_MUTATIONS, REGISTRY_CHUNK_DATA_CAPACITY,
        REGISTRY_CHUNK_ID,
    },
    error::{ApplyError, KernelResult},
    network::NetworkId,
    store::Batch,
};

use hellas_xet::{SingleChunkHasher, XetHash};

/// Body version every registry chunk carries. Decode rejects any other
/// value, so a future body shape needs a new number rather than a new
/// optional field.
const REGISTRY_CHUNK_VERSION: u8 = 2;

/// Longest value that fits [`MAX_REGISTRY_CHUNKS`] chunks.
pub const MAX_REGISTRY_VALUE_LEN: usize = MAX_REGISTRY_CHUNKS * REGISTRY_CHUNK_DATA_CAPACITY;

/// The complete `chunk_id` preimage, at its widest.
///
/// `SingleChunkHasher::update` asserts rather than errors once a preimage
/// reaches `MIN_CHUNK_SIZE`, and this hash runs on the apply path, where
/// a panic is a node halt rather than a rejected transaction. Every term
/// here is a compile-time maximum, so the bound below is decided by the
/// compiler and not by the values a caller passes.
const CHUNK_ID_PREIMAGE_MAX: usize = REGISTRY_CHUNK_ID.len()
    + NetworkId::MAX_ENCODED_SIZE
    + <u8 as Encode>::MAX_ENCODED_SIZE
    + ID_LENGTH
    + <u8 as Encode>::MAX_ENCODED_SIZE;

const _: () = assert!(
    CHUNK_ID_PREIMAGE_MAX < hellas_xet::MIN_CHUNK_SIZE,
    "registry chunk id preimage must fit one Xet chunk"
);

/// Registry namespace a chunk id is derived under.
///
/// Records of different kinds are keyed by raw 32-byte values that can
/// legitimately be equal — the same edge names both a payment record and
/// a lease record. The namespace enters the id preimage so those two
/// never derive one id.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryNamespace {
    /// Keyed by payment edge.
    PaymentClose,
    /// Keyed by bond edge.
    BondLease,
}

impl RegistryNamespace {
    /// Returns the canonical one-byte namespace tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PaymentClose => 0,
            Self::BondLease => 1,
        }
    }

    /// Decodes a canonical one-byte namespace tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::PaymentClose),
            1 => Some(Self::BondLease),
            _ => None,
        }
    }
}

impl Encode for RegistryNamespace {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[self.tag()]);
    }
}

impl Decode for RegistryNamespace {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, consumed) = u8::decode(buf)?;
        Self::from_tag(byte)
            .map(|namespace| (namespace, consumed))
            .ok_or(DecodeError::InvalidTag { tag: byte })
    }
}

/// Kind of record a reassembled registry value holds.
///
/// Carried by every chunk so a reader knows what it is assembling before
/// it has assembled it, and so a chunk written under one record kind can
/// never be read back as another.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryRecordTag {
    /// Pending payment state.
    PaymentPending,
    /// Bond lease state.
    BondLease,
}

impl RegistryRecordTag {
    /// Returns the canonical one-byte record tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PaymentPending => 0,
            Self::BondLease => 1,
        }
    }

    /// Decodes a canonical one-byte record tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::PaymentPending),
            1 => Some(Self::BondLease),
            _ => None,
        }
    }
}

impl Encode for RegistryRecordTag {
    const MAX_ENCODED_SIZE: usize = 1;
    fn encoded_size(&self) -> usize {
        1
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[self.tag()]);
    }
}

impl Decode for RegistryRecordTag {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (byte, consumed) = u8::decode(buf)?;
        Self::from_tag(byte)
            .map(|record_tag| (record_tag, consumed))
            .ok_or(DecodeError::InvalidTag { tag: byte })
    }
}

/// Stable identifier for one registry chunk slot.
///
/// Derived, never received: [`Self::derive`] is the only way to name the
/// slot a value's chunk lives in, and its domain separator is what keeps
/// a chunk id from colliding with a [`crate::CoinId`] or
/// [`crate::EdgeId`] in the shared object namespace.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistryChunkId(XetHash);

impl RegistryChunkId {
    /// Encoded length of a registry chunk identifier.
    pub const LENGTH: usize = ID_LENGTH;

    /// Reconstructs a chunk id from canonical bytes.
    ///
    /// Public for the same reason [`crate::CoinId::from_bytes`] is: ids
    /// cross the storage and RPC boundaries as bytes. Integrity lives at
    /// [`Self::derive`], the only site that mints a fresh one.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(XetHash::from_bytes(bytes))
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }

    /// Derives the slot id for one chunk of the value stored under
    /// `logical_key` in `namespace`.
    #[must_use]
    pub fn derive(
        network: NetworkId,
        namespace: RegistryNamespace,
        logical_key: [u8; ID_LENGTH],
        chunk_index: u8,
    ) -> Self {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(REGISTRY_CHUNK_ID);
        network.encode_to(&mut hasher);
        namespace.encode_to(&mut hasher);
        logical_key.encode_to(&mut hasher);
        chunk_index.encode_to(&mut hasher);
        Self(hasher.finalize())
    }
}

impl Encode for RegistryChunkId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;
    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(self.0.as_bytes());
    }
}

impl Decode for RegistryChunkId {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_fixed::<{ Self::LENGTH }>(buf).map(|(bytes, n)| (Self::from_bytes(bytes), n))
    }
}

/// One fixed-size slice of a registry value.
///
/// A chunk is self-describing: it names the value's namespace, record
/// kind, and total length, its own position, and how many bytes of its
/// fixed data array are live. The array is always written in full so
/// every stored chunk has the same encoded size regardless of how much of
/// it the value uses.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct RegistryChunk {
    namespace: RegistryNamespace,
    record_tag: RegistryRecordTag,
    chunk_index: u8,
    chunk_count: u8,
    value_len: u16,
    data_len: u8,
    data: [u8; REGISTRY_CHUNK_DATA_CAPACITY],
}

impl RegistryChunk {
    /// Returns the number of chunks `value_len` bytes split into, or
    /// `None` for an empty value or one past [`MAX_REGISTRY_VALUE_LEN`].
    ///
    /// Empty values are excluded on purpose: with zero chunks, "the value
    /// is absent" and "the value is present and empty" would be the same
    /// stored state.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "value_len <= MAX_REGISTRY_CHUNKS * capacity, so the count fits u8"
    )]
    pub const fn chunk_count_for(value_len: usize) -> Option<u8> {
        if value_len == 0 || value_len > MAX_REGISTRY_VALUE_LEN {
            return None;
        }
        Some(value_len.div_ceil(REGISTRY_CHUNK_DATA_CAPACITY) as u8)
    }

    /// Builds the chunk covering `chunk_index` of `value`.
    ///
    /// Returns `None` when `value` cannot be split — it is empty or
    /// longer than [`MAX_REGISTRY_VALUE_LEN`] — or when `chunk_index` is
    /// past the chunks it splits into.
    #[must_use]
    pub fn split(
        namespace: RegistryNamespace,
        record_tag: RegistryRecordTag,
        value: &[u8],
        chunk_index: u8,
    ) -> Option<Self> {
        let chunk_count = Self::chunk_count_for(value.len())?;
        if chunk_index >= chunk_count {
            return None;
        }
        let start = usize::from(chunk_index).checked_mul(REGISTRY_CHUNK_DATA_CAPACITY)?;
        let slice = value.get(start..)?;
        let live = slice.get(..REGISTRY_CHUNK_DATA_CAPACITY).unwrap_or(slice);
        let mut data = [0_u8; REGISTRY_CHUNK_DATA_CAPACITY];
        data.get_mut(..live.len())?.copy_from_slice(live);
        Some(Self {
            namespace,
            record_tag,
            chunk_index,
            chunk_count,
            // `chunk_count_for` bounded the length to `u8::MAX * 120`.
            value_len: u16::try_from(value.len()).ok()?,
            // `live` is at most one chunk's capacity.
            data_len: u8::try_from(live.len()).ok()?,
            data,
        })
    }

    /// Returns the namespace this chunk's value is keyed under.
    #[must_use]
    pub const fn namespace(self) -> RegistryNamespace {
        self.namespace
    }

    /// Returns the record kind this chunk's value holds.
    #[must_use]
    pub const fn record_tag(self) -> RegistryRecordTag {
        self.record_tag
    }

    /// Returns this chunk's zero-based position in its value.
    #[must_use]
    pub const fn chunk_index(self) -> u8 {
        self.chunk_index
    }

    /// Returns the number of chunks the whole value splits into.
    #[must_use]
    pub const fn chunk_count(self) -> u8 {
        self.chunk_count
    }

    /// Returns the whole value's length in bytes.
    #[must_use]
    pub const fn value_len(self) -> u16 {
        self.value_len
    }

    /// Borrows the live value bytes this chunk carries, without the
    /// zero padding that fills the rest of its fixed data array.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.get(..usize::from(self.data_len)).unwrap_or(&[])
    }

    /// Returns the live data length `chunk_index` must declare for a
    /// value of `value_len` bytes split into `chunk_count` chunks.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "both results are checked to be at most the 120-byte capacity"
    )]
    const fn expected_data_len(value_len: u16, chunk_index: u8, chunk_count: u8) -> Option<u8> {
        let index = chunk_index as usize;
        if index + 1 < chunk_count as usize {
            return Some(REGISTRY_CHUNK_DATA_CAPACITY as u8);
        }
        // The last chunk carries the remainder, which `chunk_count_for`
        // has already established is neither zero nor a whole extra chunk.
        let Some(remainder) =
            (value_len as usize).checked_sub(index * REGISTRY_CHUNK_DATA_CAPACITY)
        else {
            return None;
        };
        if remainder == 0 || remainder > REGISTRY_CHUNK_DATA_CAPACITY {
            return None;
        }
        Some(remainder as u8)
    }
}

impl Encode for RegistryChunk {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + 6 * <u8 as Encode>::MAX_ENCODED_SIZE
        + <u16 as Encode>::MAX_ENCODED_SIZE
        + REGISTRY_CHUNK_DATA_CAPACITY;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::REGISTRY_CHUNK);
        REGISTRY_CHUNK_VERSION.encode_to(writer);
        self.namespace.encode_to(writer);
        self.record_tag.encode_to(writer);
        self.chunk_index.encode_to(writer);
        self.chunk_count.encode_to(writer);
        self.value_len.encode_to(writer);
        self.data_len.encode_to(writer);
        self.data.encode_to(writer);
    }
}

impl Decode for RegistryChunk {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::REGISTRY_CHUNK)?;
        let version: u8 = decode_field(buf, &mut consumed)?;
        if version != REGISTRY_CHUNK_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let namespace = decode_field(buf, &mut consumed)?;
        let record_tag = decode_field(buf, &mut consumed)?;
        let chunk_index: u8 = decode_field(buf, &mut consumed)?;
        let chunk_count: u8 = decode_field(buf, &mut consumed)?;
        let value_len: u16 = decode_field(buf, &mut consumed)?;
        let data_len: u8 = decode_field(buf, &mut consumed)?;
        let data: [u8; REGISTRY_CHUNK_DATA_CAPACITY] = decode_field(buf, &mut consumed)?;

        // `chunk_count` is derived from `value_len`, so a stored chunk
        // that disagrees with its own length is a second encoding of a
        // state that already has one.
        if Self::chunk_count_for(usize::from(value_len)) != Some(chunk_count) {
            return Err(DecodeError::NonCanonical {
                field: "RegistryChunk.chunk_count",
            });
        }
        if chunk_index >= chunk_count {
            return Err(DecodeError::NonCanonical {
                field: "RegistryChunk.chunk_index",
            });
        }
        if Self::expected_data_len(value_len, chunk_index, chunk_count) != Some(data_len) {
            return Err(DecodeError::NonCanonical {
                field: "RegistryChunk.data_len",
            });
        }
        let padding = data
            .get(usize::from(data_len)..)
            .ok_or(DecodeError::NonCanonical {
                field: "RegistryChunk.data_len",
            })?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonCanonical {
                field: "RegistryChunk.data",
            });
        }

        Ok((
            Self {
                namespace,
                record_tag,
                chunk_index,
                chunk_count,
                value_len,
                data_len,
                data,
            },
            consumed,
        ))
    }
}

/// One registry slot write produced by an applied operation.
///
/// The slot's whole post-state, not a delta: `Some(chunk)` means the
/// slot holds exactly that chunk afterwards and `None` means it holds
/// nothing. A host that replays a mutation therefore needs no knowledge
/// of what the slot held before.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct RegistryMutation {
    id: RegistryChunkId,
    chunk: Option<RegistryChunk>,
}

impl RegistryMutation {
    /// The slot every unused [`RegistryDiff`] entry holds.
    const EMPTY: Self = Self {
        id: RegistryChunkId::from_bytes([0; RegistryChunkId::LENGTH]),
        chunk: None,
    };

    /// Stores `chunk` in the slot named by `id`.
    #[must_use]
    pub const fn write(id: RegistryChunkId, chunk: RegistryChunk) -> Self {
        Self {
            id,
            chunk: Some(chunk),
        }
    }

    /// Empties the slot named by `id`.
    #[must_use]
    pub const fn delete(id: RegistryChunkId) -> Self {
        Self { id, chunk: None }
    }

    /// Returns the slot this mutation writes.
    #[must_use]
    pub const fn id(self) -> RegistryChunkId {
        self.id
    }

    /// Returns the slot's post-state: the stored chunk, or `None` for a
    /// deletion.
    #[must_use]
    pub const fn chunk(self) -> Option<RegistryChunk> {
        self.chunk
    }

    /// Applies this mutation to `batch`.
    fn fold<B: Batch>(self, batch: &mut B) -> KernelResult<()> {
        match self.chunk {
            // Replacing a chunk is a remove followed by an insert, the
            // same two steps a coin or edge slot takes; the removed
            // value is not compared because a mutation names the slot's
            // post-state rather than a compare-and-swap. The prior value
            // was read during validation, and [`Batch`] forbids anything
            // interleaving between validation and fold.
            Some(chunk) => {
                let _ = batch.remove_registry_chunk(self.id);
                batch
                    .insert_registry_chunk(self.id, chunk)
                    .map_err(|reason| ApplyError::RegistryChunkInsertRejected {
                        id: self.id,
                        reason,
                    })
            }
            // A deletion that finds nothing is a store contract
            // violation: the transition that emitted it read the record
            // it is deleting.
            None => batch
                .remove_registry_chunk(self.id)
                .map(|_| ())
                .ok_or(ApplyError::MissingRegistryChunk { id: self.id }),
        }
    }
}

/// Reason a [`RegistryMutation`] could not join a [`RegistryDiff`].
///
/// Both variants are transition bugs rather than user input: the
/// operation decides which slots it writes before it writes any of them.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum RegistryDiffError {
    /// The diff already holds [`MAX_REGISTRY_MUTATIONS`] mutations.
    Full,

    /// Another mutation in the diff already writes this slot.
    Duplicate {
        /// Slot named twice.
        id: RegistryChunkId,
    },
}

/// Bounded, ordered registry writes one applied operation produces.
///
/// Ordered because the host replays it into durable storage in exactly
/// this order, and duplicate-free because two writes to one slot inside
/// a single operation would make the stored result depend on replay
/// order rather than on the operation. Both rules are enforced at
/// [`Self::push`], so a diff that exists is a diff a host can replay.
///
/// The width is [`MAX_REGISTRY_MUTATIONS`] and not a caller-chosen
/// parameter: it is how much registry work one operation may cost a
/// host, which is a protocol constant rather than a local choice.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RegistryDiff {
    mutations: [RegistryMutation; MAX_REGISTRY_MUTATIONS],
    len: usize,
}

/// Prints only the live mutations, for the same reason [`crate::List`]
/// does: the dead tail is eleven identical empty slots and would bury
/// the one that matters in any assertion message.
impl core::fmt::Debug for RegistryDiff {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl RegistryDiff {
    /// Creates a diff with no mutations.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            mutations: [RegistryMutation::EMPTY; MAX_REGISTRY_MUTATIONS],
            len: 0,
        }
    }

    /// Appends `mutation`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryDiffError::Full`] once the diff holds
    /// [`MAX_REGISTRY_MUTATIONS`] mutations, or
    /// [`RegistryDiffError::Duplicate`] if another mutation already
    /// writes the same slot.
    pub fn push(&mut self, mutation: RegistryMutation) -> KernelResult<(), RegistryDiffError> {
        if self.contains(mutation.id) {
            return Err(RegistryDiffError::Duplicate { id: mutation.id });
        }
        let slot = self
            .mutations
            .get_mut(self.len)
            .ok_or(RegistryDiffError::Full)?;
        *slot = mutation;
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Returns the number of mutations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the operation wrote no registry slot.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrows the mutations in replay order.
    #[must_use]
    pub fn as_slice(&self) -> &[RegistryMutation] {
        self.mutations.get(..self.len).unwrap_or(&[])
    }

    /// Iterates over the mutations in replay order.
    pub fn iter(&self) -> core::slice::Iter<'_, RegistryMutation> {
        self.as_slice().iter()
    }

    /// Returns true when some mutation writes the slot named by `id`.
    #[must_use]
    pub fn contains(&self, id: RegistryChunkId) -> bool {
        self.iter().any(|mutation| mutation.id == id)
    }

    /// Applies every mutation to `batch`, in order.
    pub(crate) fn fold<B: Batch>(&self, batch: &mut B) -> KernelResult<()> {
        for mutation in self {
            mutation.fold(batch)?;
        }
        Ok(())
    }
}

impl Default for RegistryDiff {
    fn default() -> Self {
        Self::empty()
    }
}

impl<'a> IntoIterator for &'a RegistryDiff {
    type Item = &'a RegistryMutation;
    type IntoIter = core::slice::Iter<'a, RegistryMutation>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "the fold tests build a fixed, statically bounded four-slot store"
)]
mod tests {
    use super::*;
    use crate::{
        error::InsertError,
        object::{Coin, Edge},
        primitive::{CoinId, EdgeId},
    };

    /// Registry-only staging area with four declared slots.
    ///
    /// Coin and edge writes are refused rather than stored: these tests
    /// are about what a registry mutation does to a slot, and a batch
    /// that quietly accepted an edge write would let a fold bug that
    /// wrote to the wrong object kind pass.
    struct RegistryOnlyBatch {
        slots: [(RegistryChunkId, Option<RegistryChunk>); 4],
    }

    impl RegistryOnlyBatch {
        fn new(ids: [RegistryChunkId; 4]) -> Self {
            Self {
                slots: ids.map(|id| (id, None)),
            }
        }

        fn slot(&mut self, id: RegistryChunkId) -> Option<&mut Option<RegistryChunk>> {
            self.slots
                .iter_mut()
                .find_map(|(slot_id, chunk)| (*slot_id == id).then_some(chunk))
        }
    }

    impl Batch for RegistryOnlyBatch {
        fn coin(&self, _id: CoinId) -> Option<Coin> {
            None
        }

        fn insert_coin(&mut self, _id: CoinId, _coin: Coin) -> KernelResult<(), InsertError> {
            Err(InsertError::Unavailable)
        }

        fn remove_coin(&mut self, _id: CoinId) -> Option<Coin> {
            None
        }

        fn edge(&self, _id: EdgeId) -> Option<Edge> {
            None
        }

        fn insert_edge(&mut self, _id: EdgeId, _edge: Edge) -> KernelResult<(), InsertError> {
            Err(InsertError::Unavailable)
        }

        fn remove_edge(&mut self, _id: EdgeId) -> Option<Edge> {
            None
        }

        fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
            self.slots
                .iter()
                .find_map(|(slot_id, chunk)| (*slot_id == id).then_some(*chunk))
                .flatten()
        }

        fn insert_registry_chunk(
            &mut self,
            id: RegistryChunkId,
            chunk: RegistryChunk,
        ) -> KernelResult<(), InsertError> {
            match self.slot(id) {
                None => Err(InsertError::Unavailable),
                Some(Some(_)) => Err(InsertError::Exists),
                Some(slot) => {
                    *slot = Some(chunk);
                    Ok(())
                }
            }
        }

        fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
            self.slot(id)?.take()
        }

        fn commit(self) {}
    }

    fn network() -> NetworkId {
        NetworkId::new("hellas-registry-test").expect("legal network id")
    }

    fn slot_id(index: u8) -> RegistryChunkId {
        RegistryChunkId::derive(
            network(),
            RegistryNamespace::BondLease,
            [0x5a; ID_LENGTH],
            index,
        )
    }

    fn chunk(byte: u8) -> RegistryChunk {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &[byte; 7],
            0,
        )
        .expect("seven bytes split into one chunk")
    }

    fn ids() -> [RegistryChunkId; 4] {
        [slot_id(0), slot_id(1), slot_id(2), slot_id(3)]
    }

    #[test]
    fn folding_writes_creates_then_replaces_the_slot_contents() {
        let mut batch = RegistryOnlyBatch::new(ids());

        let mut create = RegistryDiff::empty();
        create
            .push(RegistryMutation::write(slot_id(0), chunk(0x11)))
            .expect("one mutation");
        create.fold(&mut batch).expect("create folds");
        assert_eq!(batch.registry_chunk(slot_id(0)), Some(chunk(0x11)));

        // A record that advances rewrites its own slot; the occupied
        // slot must not read back as `InsertError::Exists`.
        let mut replace = RegistryDiff::empty();
        replace
            .push(RegistryMutation::write(slot_id(0), chunk(0x22)))
            .expect("one mutation");
        replace.fold(&mut batch).expect("replace folds");
        assert_eq!(batch.registry_chunk(slot_id(0)), Some(chunk(0x22)));
    }

    #[test]
    fn folding_a_delete_empties_the_slot() {
        let mut batch = RegistryOnlyBatch::new(ids());
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::write(slot_id(1), chunk(0x33)))
            .expect("write");
        diff.fold(&mut batch).expect("write folds");

        let mut delete = RegistryDiff::empty();
        delete
            .push(RegistryMutation::delete(slot_id(1)))
            .expect("delete");
        delete.fold(&mut batch).expect("delete folds");

        assert_eq!(batch.registry_chunk(slot_id(1)), None);
    }

    /// A transition emits a deletion only for a record it just read, so
    /// a deletion that finds nothing means the store changed underneath
    /// the kernel — the same reading a vanished coin gets.
    #[test]
    fn folding_a_delete_of_an_absent_slot_is_a_store_contract_violation() {
        let mut batch = RegistryOnlyBatch::new(ids());
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::delete(slot_id(2)))
            .expect("delete");

        assert_eq!(
            diff.fold(&mut batch),
            Err(ApplyError::MissingRegistryChunk { id: slot_id(2) }),
        );
    }

    /// The host declares every slot the kernel may write. An undeclared
    /// one is the parallel-execution safety property, not a store that
    /// grows on demand.
    #[test]
    fn folding_a_write_to_an_undeclared_slot_is_rejected() {
        let mut batch = RegistryOnlyBatch::new(ids());
        let undeclared = slot_id(9);
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::write(undeclared, chunk(0x44)))
            .expect("write");

        assert_eq!(
            diff.fold(&mut batch),
            Err(ApplyError::RegistryChunkInsertRejected {
                id: undeclared,
                reason: InsertError::Unavailable,
            }),
        );
    }

    /// Replay order is the diff's order, and a fold that stopped early
    /// would leave the store holding a prefix of what the outcome
    /// promised its host.
    #[test]
    fn folding_applies_every_mutation_in_order() {
        let mut batch = RegistryOnlyBatch::new(ids());
        let mut seed = RegistryDiff::empty();
        seed.push(RegistryMutation::write(slot_id(3), chunk(0x55)))
            .expect("seed");
        seed.fold(&mut batch).expect("seed folds");

        // The widest diff this kernel produces, and the two kinds mixed:
        // a fold that stopped after the write would leave the deleted
        // slot occupied, which is the prefix its host was promised was
        // whole.
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::write(slot_id(0), chunk(0x66)))
            .expect("first");
        diff.push(RegistryMutation::delete(slot_id(3)))
            .expect("second");
        assert_eq!(diff.len(), MAX_REGISTRY_MUTATIONS);
        diff.fold(&mut batch).expect("diff folds");

        assert_eq!(batch.registry_chunk(slot_id(0)), Some(chunk(0x66)));
        assert_eq!(batch.registry_chunk(slot_id(1)), None);
        assert_eq!(batch.registry_chunk(slot_id(2)), None);
        assert_eq!(batch.registry_chunk(slot_id(3)), None);
    }
}
