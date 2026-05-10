use super::{
    Access, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, OpenCoins, PartyCoins, Resolve,
    ResolveKind, duplicate, empty_coins, empty_edges, one_edge, units,
};
use crate::{
    context::{Context, Cost},
    error::{ApplyError, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge, Parties},
    primitive::{CoinId, Digest, EdgeId, TermsHash},
    store::Tx,
    terms::Terms,
};

/// Funding consumed by an edge open.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
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
        self.maker()
            .as_slice()
            .first()
            .or_else(|| self.taker().as_slice().first())
            .copied()
    }

    fn iter(&self) -> impl Iterator<Item = CoinId> + '_ {
        self.maker().iter().chain(self.taker().iter())
    }
}

/// Open one edge by locking bounded bilateral funding.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Open {
    funding: Funding,
    terms: Terms,
    output: EdgeId,
}

impl Open {
    /// Creates an open operation from concrete terms.
    #[must_use]
    pub fn from_terms(funding: Funding, terms: Terms) -> Self {
        let output = Self::id(&funding, &terms);
        Self {
            funding,
            terms,
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
    pub const fn parties(self) -> Parties {
        self.terms.parties()
    }

    /// Returns the edge produced by the open.
    #[must_use]
    pub const fn output(self) -> EdgeId {
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

        let Some(ids) = List::new(ids, self.funding.len()) else {
            return List::all(ids);
        };
        ids
    }

    /// Returns the open terms commitment for the produced edge.
    #[must_use]
    pub fn terms(self) -> TermsHash {
        self.terms.hash()
    }

    /// Returns the deterministic resource cost of this open.
    #[must_use]
    pub fn cost(&self) -> Cost {
        let inputs = units(self.funding.len());
        Cost::new(1, inputs.saturating_add(1), inputs.saturating_add(1), 0)
    }

    pub(super) fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
        if let Some(id) = self.duplicate_input() {
            return Err(ApplyError::DuplicateInput { id });
        }
        if tx.edge(self.output).is_some() {
            return Err(ApplyError::EdgeExists { id: self.output });
        }

        let coins = self.coins(tx)?;
        let open_fee = context.fee(self.cost()).ok_or(ApplyError::InvalidOpen {
            output: self.output,
        })?;
        let reserve = context
            .fee(self.reserve_cost())
            .ok_or(ApplyError::InvalidOpen {
                output: self.output,
            })?;
        let edge = Edge::open(&coins, self.parties(), self.terms(), open_fee, reserve).ok_or(
            ApplyError::InvalidOpen {
                output: self.output,
            },
        )?;
        Ok(Change::open(&coins, (self.output, edge)))
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

    fn id(funding: &Funding, terms: &Terms) -> EdgeId {
        let mut digest = Digest::new(crate::domain::EDGE_OPEN);

        digest.bytes(terms.hash().as_bytes());
        Self::ids(&mut digest, &funding.maker);
        Self::ids(&mut digest, &funding.taker);

        EdgeId::from_digest(digest)
    }

    fn ids(digest: &mut Digest, ids: &PartyCoins) {
        digest.usize(ids.len());

        for id in ids.iter() {
            digest.bytes(id.as_bytes());
        }
    }

    fn duplicate_input(&self) -> Option<CoinId> {
        duplicate(self.inputs().as_slice())
    }

    fn coins<T: Tx>(&self, tx: &T) -> KernelResult<OpenCoins> {
        let Some(first) = self.funding.first() else {
            return Ok(List::empty((CoinId::ZERO, Coin::ZERO)));
        };
        let first_coin = tx
            .coin(first)
            .ok_or(ApplyError::MissingCoin { id: first })?;
        let mut coins = [(first, first_coin); MAX_EDGE_INPUTS];

        for (index, id) in self.funding.iter().enumerate() {
            let coin = tx.coin(id).ok_or(ApplyError::MissingCoin { id })?;
            coins[index] = (id, coin);
        }

        List::new(coins, self.funding.len()).ok_or(ApplyError::InvalidOpen {
            output: self.output,
        })
    }
}
