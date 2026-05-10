//! Open: lock bilateral funding into one edge.
//!
//! Abstract counterpart: `models/l1.qnt::openEdge` action. Funding inputs
//! must be live coins; the action consumes them and creates an edge with
//! their summed value, matching the `coins'` / `edges'` / `liveCoins'` /
//! `liveEdges'` updates in the model.

use super::{
    Access, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, OpenCoins, PartyCoins, Resolve,
    ResolveKind, duplicate, empty_coins, empty_edges, one_edge, units,
};
use crate::{
    context::{Context, Cost},
    error::{ApplyError, InvalidOpenReason, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge, Parties},
    primitive::{CoinId, Digest, EdgeId, TermsHash},
    store::Tx,
    terms::Terms,
};

/// Funding consumed by an edge open.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Funding {
    maker: PartyCoins,
    taker: PartyCoins,
}

impl Funding {
    /// Creates bilateral edge funding.
    #[must_use]
    pub const fn new(
        maker: List<CoinId, MAX_PARTY_INPUTS>,
        taker: List<CoinId, MAX_PARTY_INPUTS>,
    ) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker funding inputs.
    #[must_use]
    pub const fn maker(&self) -> &List<CoinId, MAX_PARTY_INPUTS> {
        &self.maker
    }

    /// Returns the taker funding inputs.
    #[must_use]
    pub const fn taker(&self) -> &List<CoinId, MAX_PARTY_INPUTS> {
        &self.taker
    }

    const fn len(&self) -> usize {
        self.maker.len() + self.taker.len()
    }

    fn first(&self) -> Option<CoinId> {
        self.iter().next()
    }

    fn iter(&self) -> impl Iterator<Item = CoinId> + '_ {
        self.maker().iter().chain(self.taker().iter()).copied()
    }
}

/// Open one edge by locking bounded bilateral funding.
///
/// `terms_hash` is cached at construction. The kernel reaches for it on every
/// apply, and recomputing the BLAKE3 each time is the dominant per-op cost in
/// benchmarks; one extra 32 bytes per `Open` saves roughly half the apply
/// time at the largest batch sizes.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Open {
    funding: Funding,
    terms: Terms,
    terms_hash: TermsHash,
    output: EdgeId,
}

impl Open {
    /// Creates an open operation from concrete terms.
    #[must_use]
    pub fn from_terms(funding: Funding, terms: Terms) -> Self {
        let terms_hash = terms.hash();
        let output = Self::id(&funding, terms_hash);
        Self {
            funding,
            terms,
            terms_hash,
            output,
        }
    }

    /// Returns the funding consumed by the open.
    #[must_use]
    pub const fn funding(&self) -> &Funding {
        &self.funding
    }

    /// Returns the parties committed by the produced edge.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        self.terms.parties()
    }

    /// Returns the edge produced by the open.
    #[must_use]
    pub const fn output(&self) -> EdgeId {
        self.output
    }

    /// Returns funding coin ids in canonical operation order.
    #[must_use]
    pub fn inputs(&self) -> List<CoinId, MAX_EDGE_INPUTS> {
        let fill = self.funding.first().unwrap_or(CoinId::ZERO);
        let mut ids = [fill; MAX_EDGE_INPUTS];

        for (index, id) in self.funding.iter().enumerate() {
            ids[index] = id;
        }

        List::take(ids, self.funding.len())
    }

    /// Returns the open terms commitment for the produced edge.
    #[must_use]
    pub const fn terms(&self) -> TermsHash {
        self.terms_hash
    }

    /// Returns the deterministic resource cost of this open.
    ///
    /// One slot per funding input plus one for the produced edge.
    #[must_use]
    pub fn cost(&self) -> Cost {
        let inputs = units(self.funding.len());
        Cost::new(1, inputs.saturating_add(1), 0)
    }

    pub(super) fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
        if let Some(id) = self.duplicate_input() {
            return Err(ApplyError::DuplicateInput { id });
        }
        if tx.edge(self.output).is_some() {
            return Err(ApplyError::EdgeExists { id: self.output });
        }

        let coins = self.coins(tx)?;
        let open_fee = context
            .fee(self.cost())
            .ok_or_else(|| self.invalid(InvalidOpenReason::FeeOverflow))?;
        let reserve = context
            .fee(self.reserve_cost())
            .ok_or_else(|| self.invalid(InvalidOpenReason::ReserveOverflow))?;
        let edge = Edge::open(&coins, self.parties(), self.terms(), open_fee, reserve)
            .map_err(|reason| self.invalid(reason))?;
        Ok(Change::open(&coins, (self.output, edge)))
    }

    const fn invalid(&self, reason: InvalidOpenReason) -> ApplyError {
        ApplyError::InvalidOpen {
            output: self.output,
            reason,
        }
    }

    /// Returns the pessimistic resource cost prepaid for a future resolve.
    ///
    /// V1 opens reserve for the worst bounded resolve path so the protocol can
    /// always be paid at resolve time.
    #[must_use]
    pub fn reserve_cost(&self) -> Cost {
        Resolve::cost_for_kind(MAX_EDGE_OUTPUTS, ResolveKind::ClaimantWins)
    }

    pub(super) fn access(&self) -> Access {
        Access {
            coins: self.inputs(),
            edges: empty_edges(),
            new_coins: empty_coins(),
            new_edges: one_edge(self.output),
        }
    }

    fn id(funding: &Funding, terms_hash: TermsHash) -> EdgeId {
        let mut digest = Digest::new(crate::domain::EDGE_OPEN);

        digest.bytes(terms_hash.as_bytes());
        Self::ids(&mut digest, &funding.maker);
        Self::ids(&mut digest, &funding.taker);

        EdgeId::from_digest(digest)
    }

    fn ids(digest: &mut Digest, ids: &PartyCoins) {
        digest.usize(ids.len());

        for id in ids {
            digest.bytes(id.as_bytes());
        }
    }

    fn duplicate_input(&self) -> Option<CoinId> {
        duplicate(self.inputs().as_slice())
    }

    fn coins<T: Tx>(&self, tx: &T) -> KernelResult<OpenCoins> {
        let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
        for (index, id) in self.funding.iter().enumerate() {
            let coin = tx.coin(id).ok_or(ApplyError::MissingCoin { id })?;
            coins[index] = (id, coin);
        }
        Ok(List::take(coins, self.funding.len()))
    }
}
