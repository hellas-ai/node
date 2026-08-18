//! The one coherent finalized read a paid work channel is decided from.
//!
//! # Why one read rather than four
//!
//! A work channel is four pieces of consensus state: the tag-4 bond
//! edge, the tag-2 payment edge, the bond's lease slots, and the payment
//! edge's pending-close slot. An endpoint that fetched them one at a
//! time would be answering from up to four different states, and the
//! combinations that produces are not hypothetical — a payment edge from
//! before a contest opened, beside a lease from after the bond was timed
//! out, reads as a healthy channel and is not one.
//!
//! So [`WorkChannelSnapshot`] is one answer at one finalized block, read
//! under one database snapshot, and it carries the block it was read at
//! so a caller can say which state it acted on. The existing point
//! queries cannot be composed into this: `LightClient::get_edge` treats
//! its payload argument as a finalized *floor* and reads the
//! then-current database root, which is a different question.
//!
//! # What it does not do
//!
//! It does not authenticate the objects. In this milestone's trusted
//! mode the endpoint and the chain process share a trust boundary, and
//! the values here are unproved database replies. `finalization` proves
//! that a quorum finalized *the block*; it says nothing about whether an
//! object field in the reply belongs to that block's state. Nothing here
//! may be described as an authenticated object read until the RPC
//! carries membership and nonmembership proofs against the verified
//! state root.
//!
//! # What it does not decide
//!
//! Whether the channel is usable. This module reports what is there;
//! `hellas_rpc::protocol::work_setup` decides what that means. The shape
//! of the two registry answers is not decided here either: the kernel's
//! own [`parse_bond_lease`] and [`parse_pending_close`] are called, so
//! an endpoint and a close cannot disagree about what a slot holds.

use crate::domain::Digest;
use crate::light_client::{LatestBlock, QueryError};
use hellas_kernel::{
    BOND_LEASE_CHUNKS, Edge, EdgeId, LeaseSlots, PendingSlot, RegistryChunk, parse_bond_lease,
    parse_pending_close,
};

/// Which channel a snapshot answers for.
///
/// Both edges, because neither alone identifies the channel: the payment
/// terms name the bond, but the lease is keyed by the bond and the
/// pending record by the payment edge, so a reader that knew only one of
/// them could not derive both slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkChannelQuery {
    /// The tag-4 work-stake bond insuring the channel.
    pub bond_edge: EdgeId,
    /// The tag-2 payment edge work is paid from.
    pub payment_edge: EdgeId,
}

/// Everything one paid work channel is decided from, at one finalized
/// block.
///
/// The query travels with the answer, and the two registry answers are
/// only reachable through [`Self::lease`] and [`Self::pending`], which
/// parse against the edges in that query. A caller therefore cannot ask
/// what one channel's slots mean while holding another channel's
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkChannelSnapshot {
    query: WorkChannelQuery,
    block: LatestBlock,
    bond: Option<Edge>,
    payment: Option<Edge>,
    lease_slots: [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize],
    pending_slot: Option<RegistryChunk>,
}

impl WorkChannelSnapshot {
    /// Assembles one snapshot from objects a caller has already read at
    /// one block.
    ///
    /// The caller owes the coherence: every object must come from the
    /// same database snapshot, and that snapshot's root must be
    /// `block.state_root`. Nothing in these arguments can establish
    /// that, and this constructor does not pretend to check it — the two
    /// implementations that call it are the ones that hold the reader.
    #[must_use]
    pub const fn new(
        query: WorkChannelQuery,
        block: LatestBlock,
        bond: Option<Edge>,
        payment: Option<Edge>,
        lease_slots: [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize],
        pending_slot: Option<RegistryChunk>,
    ) -> Self {
        Self {
            query,
            block,
            bond,
            payment,
            lease_slots,
            pending_slot,
        }
    }

    /// Returns the channel this snapshot answers for.
    #[must_use]
    pub const fn query(&self) -> WorkChannelQuery {
        self.query
    }

    /// Returns the finalized block every object here was read at.
    #[must_use]
    pub const fn block(&self) -> &LatestBlock {
        &self.block
    }

    /// Returns the finalized height every object here was read at.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.block.height
    }

    /// Returns the state root every object here was read under.
    #[must_use]
    pub const fn state_root(&self) -> Digest {
        self.block.state_root
    }

    /// Returns the bond edge, or its absence.
    #[must_use]
    pub const fn bond(&self) -> Option<&Edge> {
        self.bond.as_ref()
    }

    /// Returns the payment edge, or its absence.
    #[must_use]
    pub const fn payment(&self) -> Option<&Edge> {
        self.payment.as_ref()
    }

    /// Returns the raw contents of the bond's lease slots, in slot
    /// order.
    ///
    /// Present for the wire, which has to carry them, and for tests that
    /// mutate one slot. Decisions take [`Self::lease`].
    #[must_use]
    pub const fn lease_slots(&self) -> &[Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize] {
        &self.lease_slots
    }

    /// Returns the raw contents of the payment edge's pending-close
    /// slot.
    #[must_use]
    pub const fn pending_slot(&self) -> Option<RegistryChunk> {
        self.pending_slot
    }

    /// Returns whether this bond is leased, unleased, or holding
    /// something that is neither.
    #[must_use]
    pub fn lease(&self) -> LeaseSlots {
        parse_bond_lease(self.lease_slots, self.query.bond_edge)
    }

    /// Returns whether this payment edge has a live contest, no
    /// contest, or something that is neither.
    #[must_use]
    pub fn pending(&self) -> PendingSlot {
        parse_pending_close(self.pending_slot, self.query.payment_edge)
    }
}

/// A narrow finalized read of one work channel.
///
/// Separate from [`crate::LightClient`] on purpose. This is the whole of
/// what a paid endpoint needs from a chain, and a client that does paid
/// work should not have to be handed coin queries, an activity stream,
/// and a mempool to get it. It is also what lets an endpoint be tested
/// against a state it constructs rather than a validator it runs.
pub trait FinalizedWorkView: Clone + Send + Sync + 'static {
    /// Returns every object of one channel at one finalized block.
    ///
    /// `Ok(None)` means the node has no finalized state to answer from
    /// yet — not that the channel is absent. An existing channel whose
    /// objects are all missing at a real finalized block is
    /// `Ok(Some(..))` with absent objects, and those are different
    /// facts: the first says "ask again", the second says "this is not
    /// a channel".
    fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> impl Future<Output = Result<Option<WorkChannelSnapshot>, QueryError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::{
        BondLease, NetworkId, RegistryNamespace, RegistryRecordTag, bond_lease_slots,
        pending_payment_close_slot,
    };

    fn bond() -> EdgeId {
        EdgeId::from_bytes([0x11; EdgeId::LENGTH])
    }

    fn payment() -> EdgeId {
        EdgeId::from_bytes([0x22; EdgeId::LENGTH])
    }

    fn query() -> WorkChannelQuery {
        WorkChannelQuery {
            bond_edge: bond(),
            payment_edge: payment(),
        }
    }

    fn block() -> LatestBlock {
        LatestBlock {
            height: 42,
            payload: Digest::from([0x01; 32]),
            state_root: Digest::from([0x02; 32]),
            finalization: vec![0x03],
        }
    }

    fn empty(query: WorkChannelQuery) -> WorkChannelSnapshot {
        WorkChannelSnapshot::new(query, block(), None, None, [None, None], None)
    }

    /// The canonical bytes of one bond lease, spelled out here rather
    /// than produced by the encoder this test is checking a reader of.
    ///
    /// An endpoint reads these bytes off a wire, not out of a kernel
    /// transition, so its side of the agreement is a byte layout and
    /// not a round trip. A round trip against `BondLease::encode` would
    /// pass with any two fields transposed; this does not.
    fn lease_value() -> Vec<u8> {
        let mut value = Vec::new();
        // envelope: canonical format version 1, type tag 31.
        value.extend_from_slice(&[1, 31]);
        // body version.
        value.push(2);
        value.extend_from_slice(&[0x11; 32]); // bond_edge
        value.extend_from_slice(&[0x22; 32]); // payment_edge
        value.extend_from_slice(&[0x33; 32]); // payment_terms_hash
        value.extend_from_slice(&[0x44; 32]); // private_policy_commitment
        value.extend_from_slice(&9_000_u64.to_be_bytes()); // admission_horizon
        assert_eq!(value.len(), BondLease::ENCODED_SIZE);
        value
    }

    fn lease_slots(value: &[u8]) -> [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize] {
        let slots = [0, 1].map(|index| {
            RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                value,
                index,
            )
        });
        assert!(slots.iter().all(Option::is_some), "the lease splits");
        slots
    }

    /// The two registry answers are taken against the snapshot's own
    /// query, so a snapshot of one channel cannot report another
    /// channel's lease as present.
    #[test]
    fn registry_answers_are_parsed_against_this_snapshots_own_edges() {
        let value = lease_value();
        let slots = lease_slots(&value);

        let held = WorkChannelSnapshot::new(query(), block(), None, None, slots, None);
        let LeaseSlots::Present(lease) = held.lease() else {
            panic!(
                "the canonical bytes are a readable lease, got {:?}",
                held.lease()
            );
        };
        assert_eq!(lease.bond_edge(), bond());
        assert_eq!(lease.payment_edge(), payment());
        assert_eq!(lease.admission_horizon(), 9_000);
        assert_eq!(lease.private_policy_commitment(), [0x44; 32]);
        assert_eq!(held.pending(), PendingSlot::Absent);

        // The same slot contents, under a snapshot that answers for a
        // different bond. Only the query moves.
        let other = WorkChannelQuery {
            bond_edge: EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
            payment_edge: payment(),
        };
        let elsewhere = WorkChannelSnapshot::new(other, block(), None, None, slots, None);
        assert!(matches!(elsewhere.lease(), LeaseSlots::Faulty(_)));

        assert_eq!(empty(query()).lease(), LeaseSlots::Absent);
    }

    /// The slots a snapshot reports are the slots the kernel's own
    /// transitions read, keyed by the same two edges.
    #[test]
    fn the_derived_slots_are_the_kernels_own() {
        let Some(network) = NetworkId::new("hellas-test") else {
            panic!("a short ascii id is a legal network id");
        };
        let derived = bond_lease_slots(network, bond());
        assert_ne!(derived[0], derived[1]);
        assert_ne!(
            derived[0].to_bytes(),
            pending_payment_close_slot(network, payment()).to_bytes(),
        );
    }
}
