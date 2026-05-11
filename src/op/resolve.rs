//! Resolve: consume one edge and materialize bounded payout coins.
//!
//! Abstract counterpart: `models/l1.qnt::resolveEdge` action plus the
//! `canResolve` predicate. The action's preconditions (live edge, valid
//! proof, payout sum equals edge value, payouts honor binding) are
//! enforced here before any state mutation, mirroring the Quint pattern of
//! gating an action on `canResolve(...)` before primed-variable updates.

use super::{MAX_EDGE_OUTPUTS, Payouts, Proof, ResolveCoins, ResolveKind, units};
use crate::{
    canonical::Encode,
    context::{Context, Cost},
    error::{ApplyError, InvalidResolveReason, KernelResult},
    event::Change,
    list::List,
    object::Coin,
    primitive::{CoinId, EdgeId, Key, ResolveHash, TermsHash},
    store::Batch,
    verifier::Verifier,
};

/// Resolve one edge into bounded owner-only coin payouts.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Resolve {
    input: EdgeId,
    proof: Proof,
    outputs: Payouts,
}

impl Resolve {
    /// Creates a resolve operation.
    #[must_use]
    pub const fn new(input: EdgeId, proof: Proof, outputs: List<Payout, MAX_EDGE_OUTPUTS>) -> Self {
        Self {
            input,
            proof,
            outputs,
        }
    }

    /// Returns the edge consumed by the resolve.
    #[must_use]
    pub const fn input(self) -> EdgeId {
        self.input
    }

    /// Returns the resolve proof.
    #[must_use]
    pub const fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Returns the coin payouts produced by the resolve.
    #[must_use]
    pub const fn outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        &self.outputs
    }

    /// Returns the canonical ids of the payout coins this resolve creates.
    #[must_use]
    pub fn output_ids(&self) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];

        for (index, payout) in self.outputs.iter().enumerate() {
            ids[index] = self.output_id(index, *payout);
        }

        List::take(ids, self.outputs.len())
    }

    /// Returns the deterministic resource cost of this resolve.
    #[must_use]
    pub fn cost(&self) -> Cost {
        Self::cost_for(self.outputs.len(), &self.proof)
    }

    fn cost_for(outputs: usize, proof: &Proof) -> Cost {
        Self::cost_for_kind(outputs, (*proof).kind())
    }

    /// One slot per payout output plus one for the consumed edge.
    pub(super) fn cost_for_kind(outputs: usize, kind: ResolveKind) -> Cost {
        let outputs = units(outputs);
        Cost::new(1, outputs.saturating_add(1), kind.proofs())
    }

    pub(super) fn apply<B: Batch, V: Verifier + ?Sized>(
        &self,
        context: Context,
        verifier: &V,
        batch: &B,
    ) -> KernelResult<Change> {
        self.check_outputs(batch)?;

        let coins = self.coins();
        let edge = batch
            .edge(self.input)
            .ok_or(ApplyError::MissingEdge { id: self.input })?;
        self.proof
            .accepts(context, verifier, self, edge)
            .map_err(|reason| ApplyError::InvalidProof {
                input: self.input,
                reason,
            })?;
        let fee = context
            .fee(self.cost())
            .ok_or_else(|| self.invalid(InvalidResolveReason::FeeOverflow))?;
        edge.resolves(&coins, fee)
            .map_err(|reason| self.invalid(reason))?;

        Ok(Change::resolve((self.input, edge), &coins))
    }

    const fn invalid(&self, reason: InvalidResolveReason) -> ApplyError {
        ApplyError::InvalidResolve {
            input: self.input,
            reason,
        }
    }

    /// Returns the commitment signed or proven by a resolve witness.
    #[must_use]
    pub fn hash(&self, kind: ResolveKind) -> ResolveHash {
        Self::payload_hash(self.input, kind, self.proof.terms(), &self.outputs)
    }

    /// Returns the commitment for a concrete resolve payload.
    #[must_use]
    pub fn payload_hash(
        input: EdgeId,
        kind: ResolveKind,
        terms: TermsHash,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> ResolveHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crate::domain::RESOLVE);
        input.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        terms.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        ResolveHash::from_bytes(*hasher.finalize().as_bytes())
    }

    fn check_outputs<B: Batch>(&self, batch: &B) -> KernelResult<()> {
        for (index, output) in self.outputs.iter().enumerate() {
            let id = self.output_id(index, *output);
            if batch.coin(id).is_some() {
                return Err(ApplyError::OutputExists { id });
            }
        }
        Ok(())
    }

    fn coins(&self) -> ResolveCoins {
        let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
        for (index, output) in self.outputs.iter().enumerate() {
            coins[index] = output.coin(self.input, index);
        }
        List::take(coins, self.outputs.len())
    }

    fn output_id(&self, index: usize, payout: Payout) -> CoinId {
        payout.id(self.input, index)
    }
}

/// Coin payout requested by an edge resolve.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Payout {
    owner: Key,
    value: u64,
}

impl crate::canonical::Encode for Payout {
    const MAX_ENCODED_SIZE: usize = Key::LENGTH + 8;
    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }
    fn encode_to<W: crate::canonical::Writer + ?Sized>(&self, writer: &mut W) {
        self.owner.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl crate::canonical::Decode for Payout {
    fn decode(buf: &[u8]) -> Result<(Self, usize), crate::canonical::DecodeError> {
        let (owner, n) = Key::decode(buf)?;
        let (value, m) = u64::decode(&buf[n..])?;
        Ok((Self { owner, value }, n + m))
    }
}

impl Payout {
    /// Creates a resolve payout.
    #[must_use]
    pub const fn new(owner: Key, value: u64) -> Self {
        Self { owner, value }
    }

    /// Returns the output coin owner.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the output coin value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Derives the canonical output coin id for this payout position.
    #[must_use]
    pub fn id(self, edge: EdgeId, index: usize) -> CoinId {
        CoinId::payout(edge, index, self.owner)
    }

    fn coin(self, edge: EdgeId, index: usize) -> (CoinId, Coin) {
        (self.id(edge, index), Coin::issue(self.owner, self.value))
    }
}
