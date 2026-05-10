//! Operation vocabulary, events, and the validate-then-fold transition machinery.

use crate::{
    context::{Context, Cost},
    error::{ApplyError, KernelResult},
    event::Change,
    list::List,
    object::{Coin, Edge, Parties},
    primitive::{CoinId, Digest, EdgeId, Key, Party, ProtocolCode, ResolveHash, Sig, TermsHash},
    store::Tx,
    terms::Terms,
};

const SEAL_LENGTH: usize = 32;

/// Maximum coins that can fund one party in a v1 edge open.
///
/// Four inputs per party covers the expected one-or-two-coin channel open while
/// keeping validation fully bounded. Raising this changes operation shape,
/// resource costs, and model bounds, so it is a chain-version change.
pub const MAX_PARTY_INPUTS: usize = 4;

/// Maximum coins that can fund one v1 edge open.
pub const MAX_EDGE_INPUTS: usize = MAX_PARTY_INPUTS * 2;

/// Maximum coins that can be produced by one v1 edge resolve.
///
/// Four outputs leaves room for maker, taker, and small protocol-defined splits
/// without making every resolve pay for an unbounded payout fanout. Raising this
/// is also a chain-version change.
pub const MAX_EDGE_OUTPUTS: usize = 4;

type PartyCoins = List<CoinId, MAX_PARTY_INPUTS>;
type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type Payouts = List<Payout, MAX_EDGE_OUTPUTS>;
type ResolveCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;
type EdgeList = List<EdgeId, 1>;

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
}

/// A protocol operation submitted to the Hellas kernel.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Op {
    /// Open one edge by locking bounded bilateral funding.
    Open(Open),

    /// Resolve one edge into bounded owner-only coin payouts.
    Resolve(Resolve),
}

impl Op {
    pub(crate) fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
        match self {
            Self::Open(op) => op.apply(context, tx),
            Self::Resolve(op) => op.apply(context, tx),
        }
    }

    /// Returns the deterministic resource cost of this operation.
    #[must_use]
    pub fn cost(&self) -> Cost {
        match self {
            Self::Open(op) => op.cost(),
            Self::Resolve(op) => op.cost(),
        }
    }

    /// Returns the deterministic state access set of this operation.
    #[must_use]
    pub fn access(&self) -> Access {
        match self {
            Self::Open(op) => op.access(),
            Self::Resolve(op) => op.access(),
        }
    }

    /// Returns true if this operation touches any state slot also touched by
    /// `other`.
    #[must_use]
    pub fn conflicts(&self, other: &Self) -> bool {
        self.access().conflicts(&other.access())
    }
}

/// Deterministic state slots consumed and created by one operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Access {
    coins: List<CoinId, MAX_EDGE_INPUTS>,
    edges: EdgeList,
    new_coins: List<CoinId, MAX_EDGE_OUTPUTS>,
    new_edges: EdgeList,
}

impl Access {
    /// Returns consumed coin ids.
    #[must_use]
    pub const fn coins(&self) -> &List<CoinId, MAX_EDGE_INPUTS> {
        &self.coins
    }

    /// Returns consumed edge ids.
    #[must_use]
    pub const fn edges(&self) -> &EdgeList {
        &self.edges
    }

    /// Returns created coin ids.
    #[must_use]
    pub const fn new_coins(&self) -> &List<CoinId, MAX_EDGE_OUTPUTS> {
        &self.new_coins
    }

    /// Returns created edge ids.
    #[must_use]
    pub const fn new_edges(&self) -> &EdgeList {
        &self.new_edges
    }

    /// Returns true if two declared access sets touch any common state slot.
    #[must_use]
    pub fn conflicts(&self, other: &Self) -> bool {
        self.coin_conflicts(other) || self.edge_conflicts(other)
    }

    fn coin_conflicts(&self, other: &Self) -> bool {
        overlaps(self.coins(), other.coins())
            || overlaps(self.coins(), other.new_coins())
            || overlaps(self.new_coins(), other.coins())
            || overlaps(self.new_coins(), other.new_coins())
    }

    fn edge_conflicts(&self, other: &Self) -> bool {
        overlaps(self.edges(), other.edges())
            || overlaps(self.edges(), other.new_edges())
            || overlaps(self.new_edges(), other.edges())
            || overlaps(self.new_edges(), other.new_edges())
    }
}

/// Open one edge by locking bounded bilateral funding.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Open {
    funding: Funding,
    parties: Parties,
    output: EdgeId,
    terms: TermsHash,
}

impl Open {
    /// Creates an open operation with its canonical output id.
    #[must_use]
    pub fn new(funding: Funding, parties: Parties, terms: TermsHash) -> Self {
        let output = Self::id(&funding, parties, terms);
        Self {
            funding,
            parties,
            output,
            terms,
        }
    }

    /// Creates an open operation from concrete terms.
    #[must_use]
    pub fn from_terms(funding: Funding, terms: Terms) -> Self {
        Self::new(funding, terms.parties(), terms.hash())
    }

    /// Returns the funding consumed by the open.
    #[must_use]
    pub const fn funding(&self) -> &Funding {
        &self.funding
    }

    /// Returns the parties committed by the produced edge.
    #[must_use]
    pub const fn parties(self) -> Parties {
        self.parties
    }

    /// Returns the edge produced by the open.
    #[must_use]
    pub const fn output(self) -> EdgeId {
        self.output
    }

    /// Returns funding coin ids in canonical operation order.
    #[must_use]
    pub fn inputs(&self) -> List<CoinId, MAX_EDGE_INPUTS> {
        let maker = self.funding.maker.as_slice();
        let taker = self.funding.taker.as_slice();
        let fill = maker
            .first()
            .or_else(|| taker.first())
            .copied()
            .unwrap_or(CoinId::from_bytes([0; CoinId::LENGTH]));
        let mut ids = [fill; MAX_EDGE_INPUTS];

        for (index, id) in maker
            .iter()
            .copied()
            .chain(taker.iter().copied())
            .enumerate()
        {
            ids[index] = id;
        }

        let Some(ids) = List::new(ids, self.funding.len()) else {
            return List::all(ids);
        };
        ids
    }

    /// Returns the open terms commitment for the produced edge.
    #[must_use]
    pub const fn terms(self) -> TermsHash {
        self.terms
    }

    /// Returns the deterministic resource cost of this open.
    #[must_use]
    pub fn cost(&self) -> Cost {
        let inputs = units(self.funding.len());
        Cost::new(1, inputs.saturating_add(1), inputs.saturating_add(1), 0)
    }

    fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
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
        let edge = Edge::open(&coins, self.parties, self.terms, open_fee, reserve).ok_or(
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

    fn access(&self) -> Access {
        Access {
            coins: self.inputs(),
            edges: empty_edges(),
            new_coins: empty_coins(),
            new_edges: one_edge(self.output),
        }
    }

    fn id(funding: &Funding, parties: Parties, terms: TermsHash) -> EdgeId {
        let mut digest = Digest::new(b"hellas.edge.edge.v1");

        digest.bytes(terms.as_bytes());
        digest.bytes(parties.maker().as_bytes());
        digest.bytes(parties.taker().as_bytes());
        Self::ids(&mut digest, Party::Maker, &funding.maker);
        Self::ids(&mut digest, Party::Taker, &funding.taker);

        EdgeId::from_digest(digest)
    }

    fn ids(digest: &mut Digest, party: Party, ids: &PartyCoins) {
        digest.u8(party.tag());
        digest.usize(ids.len());

        for id in ids.iter() {
            digest.bytes(id.as_bytes());
        }
    }

    fn duplicate_input(&self) -> Option<CoinId> {
        let maker = self.funding.maker.as_slice();
        let taker = self.funding.taker.as_slice();

        let mut outer = 0;
        while outer < maker.len() {
            let mut inner = outer + 1;
            while inner < maker.len() {
                if maker[outer] == maker[inner] {
                    return Some(maker[outer]);
                }
                inner += 1;
            }
            for id in taker {
                if maker[outer] == *id {
                    return Some(maker[outer]);
                }
            }
            outer += 1;
        }

        outer = 0;
        while outer < taker.len() {
            let mut inner = outer + 1;
            while inner < taker.len() {
                if taker[outer] == taker[inner] {
                    return Some(taker[outer]);
                }
                inner += 1;
            }
            outer += 1;
        }

        None
    }

    fn coins<T: Tx>(&self, tx: &T) -> KernelResult<OpenCoins> {
        let maker = self.funding.maker.as_slice();
        let taker = self.funding.taker.as_slice();
        let Some(first) = maker.first().or_else(|| taker.first()).copied() else {
            let fill = (CoinId::from_bytes([0; CoinId::LENGTH]), Coin::zero());
            return List::new([fill; MAX_EDGE_INPUTS], 0).ok_or(ApplyError::InvalidOpen {
                output: self.output,
            });
        };
        let first_coin = tx
            .coin(first)
            .ok_or(ApplyError::MissingCoin { id: first })?;
        let mut coins = [(first, first_coin); MAX_EDGE_INPUTS];

        for (index, id) in maker
            .iter()
            .copied()
            .chain(taker.iter().copied())
            .enumerate()
        {
            let coin = tx.coin(id).ok_or(ApplyError::MissingCoin { id })?;
            coins[index] = (id, coin);
        }

        List::new(coins, self.funding.len()).ok_or(ApplyError::InvalidOpen {
            output: self.output,
        })
    }
}

/// Resolve one edge into bounded owner-only coin payouts.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
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
    pub const fn proof(&self) -> Proof {
        self.proof
    }

    /// Returns the coin payouts produced by the resolve.
    #[must_use]
    pub const fn outputs(&self) -> &List<Payout, MAX_EDGE_OUTPUTS> {
        &self.outputs
    }

    /// Returns the canonical ids of the payout coins this resolve creates.
    #[must_use]
    pub fn output_ids(&self) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_EDGE_OUTPUTS];

        for (index, payout) in self.outputs.iter().enumerate() {
            ids[index] = self.output_id(index, payout);
        }

        let Some(ids) = List::new(ids, self.outputs.len()) else {
            return List::all(ids);
        };
        ids
    }

    /// Returns the deterministic resource cost of this resolve.
    #[must_use]
    pub fn cost(&self) -> Cost {
        Self::cost_for(self.outputs.len(), self.proof)
    }

    fn cost_for(outputs: usize, proof: Proof) -> Cost {
        Self::cost_for_kind(outputs, proof.kind())
    }

    fn cost_for_kind(outputs: usize, kind: ResolveKind) -> Cost {
        let outputs = units(outputs);
        Cost::new(
            1,
            outputs.saturating_add(1),
            outputs.saturating_add(1),
            kind.proofs(),
        )
    }

    fn apply<T: Tx>(&self, context: Context, tx: &T) -> KernelResult<Change> {
        if let Some(id) = self.duplicate_output() {
            return Err(ApplyError::DuplicateOutput { id });
        }
        self.check_outputs(tx)?;

        let coins = self.coins()?;
        let edge = tx
            .edge(self.input)
            .ok_or(ApplyError::MissingEdge { id: self.input })?;
        if !self.proof.accepts(context, self, edge) {
            return Err(ApplyError::InvalidProof { input: self.input });
        }
        let fee = context
            .fee(self.cost())
            .ok_or(ApplyError::InvalidResolve { input: self.input })?;
        if !edge.resolves(&coins, fee) {
            return Err(ApplyError::InvalidResolve { input: self.input });
        }

        Change::resolve((self.input, edge), &coins)
    }

    fn access(&self) -> Access {
        Access {
            coins: empty_coins(),
            edges: one_edge(self.input),
            new_coins: self.output_ids(),
            new_edges: empty_edges(),
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
        let mut digest = Digest::new(b"hellas.edge.resolve.v1");

        digest.bytes(input.as_bytes());
        digest.u8(kind.tag());
        digest.bytes(terms.as_bytes());
        digest.usize(outputs.len());
        for output in outputs.iter() {
            digest.bytes(output.owner().as_bytes());
            digest.u64(output.value());
        }

        ResolveHash::from_digest(digest)
    }

    fn duplicate_output(&self) -> Option<CoinId> {
        let outputs = self.outputs.as_slice();
        let mut outer = 0;
        while outer < outputs.len() {
            let mut inner = outer + 1;
            while inner < outputs.len() {
                if self.output_id(outer, outputs[outer]) == self.output_id(inner, outputs[inner]) {
                    return Some(self.output_id(outer, outputs[outer]));
                }
                inner += 1;
            }
            outer += 1;
        }
        None
    }

    fn check_outputs<T: Tx>(&self, tx: &T) -> KernelResult<()> {
        for (index, output) in self.outputs.iter().enumerate() {
            let id = self.output_id(index, output);
            if tx.coin(id).is_some() {
                return Err(ApplyError::OutputExists { id });
            }
        }
        Ok(())
    }

    fn coins(&self) -> KernelResult<ResolveCoins> {
        let outputs = self.outputs.as_slice();
        let Some(first) = outputs.first().copied() else {
            let fill = (CoinId::from_bytes([0; CoinId::LENGTH]), Coin::zero());
            return List::new([fill; MAX_EDGE_OUTPUTS], 0)
                .ok_or(ApplyError::InvalidResolve { input: self.input });
        };
        let mut coins = [first.coin(self.input, 0); MAX_EDGE_OUTPUTS];

        for (index, output) in outputs.iter().copied().enumerate() {
            coins[index] = output.coin(self.input, index);
        }

        List::new(coins, outputs.len()).ok_or(ApplyError::InvalidResolve { input: self.input })
    }

    fn output_id(&self, index: usize, payout: Payout) -> CoinId {
        payout.id(self.input, index)
    }
}

/// Universal resolve witness kind.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ResolveKind {
    /// Degenerate modelling witness.
    Basic,

    /// Cooperative resolve agreed by both parties.
    Agreement,

    /// Timeout resolve under the committed terms.
    Timeout,

    /// Correctness dispute resolved for the claimant.
    ClaimantWins,

    /// Correctness dispute resolved for the challenger.
    ChallengerWins,
}

impl ResolveKind {
    /// Returns the canonical one-byte resolve witness tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Basic => 0,
            Self::Agreement => 1,
            Self::Timeout => 2,
            Self::ClaimantWins => 3,
            Self::ChallengerWins => 4,
        }
    }

    const fn proofs(self) -> u64 {
        match self {
            Self::Basic | Self::Timeout => 1,
            Self::Agreement | Self::ClaimantWins | Self::ChallengerWins => 2,
        }
    }
}

/// Cooperative resolve witness signed by both edge parties.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Agreement {
    maker: Sig,
    taker: Sig,
}

impl Agreement {
    /// Creates a cooperative agreement witness.
    #[must_use]
    pub const fn new(maker: Sig, taker: Sig) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker signature.
    #[must_use]
    pub const fn maker(self) -> Sig {
        self.maker
    }

    /// Returns the taker signature.
    #[must_use]
    pub const fn taker(self) -> Sig {
        self.taker
    }

    fn accepts(self, parties: Parties, hash: ResolveHash) -> bool {
        self.maker.verifies(parties.maker(), hash) && self.taker.verifies(parties.taker(), hash)
    }
}

/// Compact mode-specific proof result for a dispute outcome.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Seal([u8; Self::LENGTH]);

impl Seal {
    /// Encoded length of a compact dispute seal.
    pub const LENGTH: usize = SEAL_LENGTH;

    /// Creates a dispute seal from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Creates a deterministic dispute seal placeholder for modelling.
    ///
    /// This is forgeable and not a cryptographic proof. The kernel accepts this
    /// shape only when built with the `fake-crypto` feature.
    #[must_use]
    pub fn placeholder(protocol: ProtocolCode, kind: ResolveKind, hash: ResolveHash) -> Self {
        let mut digest = Digest::new(b"hellas.seal.placeholder.v1");

        digest.u8(protocol.get());
        digest.u8(kind.tag());
        digest.bytes(hash.as_bytes());

        Self(digest.finish())
    }

    fn accepts(self, protocol: ProtocolCode, kind: ResolveKind, hash: ResolveHash) -> bool {
        #[cfg(feature = "fake-crypto")]
        {
            self == Self::placeholder(protocol, kind, hash)
        }

        #[cfg(not(feature = "fake-crypto"))]
        {
            let _ = (self, protocol, kind, hash);
            false
        }
    }
}

/// Bounded proof carried by an edge resolve.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Proof {
    /// Degenerate modelling witness.
    Basic {
        /// Terms commitment this proof opens under.
        terms: TermsHash,
    },

    /// Cooperative agreement witness signed by both parties.
    Agreement {
        /// Terms commitment this proof opens under.
        terms: TermsHash,
        /// Agreement signatures.
        agreement: Agreement,
    },

    /// Timeout witness under committed terms.
    Timeout {
        /// Concrete terms revealed to check the timeout.
        terms: Terms,
    },

    /// Correctness witness resolving for the claimant.
    ClaimantWins {
        /// Concrete terms revealed to select the mode verifier.
        terms: Terms,
        /// Compact mode-specific verifier result.
        seal: Seal,
    },

    /// Correctness witness resolving for the challenger.
    ChallengerWins {
        /// Concrete terms revealed to select the mode verifier.
        terms: Terms,
        /// Compact mode-specific verifier result.
        seal: Seal,
    },
}

impl Proof {
    /// Creates a basic resolve proof.
    #[must_use]
    pub const fn basic(terms: TermsHash) -> Self {
        Self::Basic { terms }
    }

    /// Creates a cooperative agreement resolve witness.
    #[must_use]
    pub const fn agreement(terms: TermsHash, agreement: Agreement) -> Self {
        Self::Agreement { terms, agreement }
    }

    /// Creates a timeout resolve witness.
    #[must_use]
    pub const fn timeout(terms: Terms) -> Self {
        Self::Timeout { terms }
    }

    /// Creates a claimant-wins resolve witness.
    #[must_use]
    pub const fn claimant_wins(terms: Terms, seal: Seal) -> Self {
        Self::ClaimantWins { terms, seal }
    }

    /// Creates a challenger-wins resolve witness.
    #[must_use]
    pub const fn challenger_wins(terms: Terms, seal: Seal) -> Self {
        Self::ChallengerWins { terms, seal }
    }

    /// Returns the resolve witness kind.
    #[must_use]
    pub const fn kind(self) -> ResolveKind {
        match self {
            Self::Basic { .. } => ResolveKind::Basic,
            Self::Agreement { .. } => ResolveKind::Agreement,
            Self::Timeout { .. } => ResolveKind::Timeout,
            Self::ClaimantWins { .. } => ResolveKind::ClaimantWins,
            Self::ChallengerWins { .. } => ResolveKind::ChallengerWins,
        }
    }

    /// Returns the terms commitment this proof opens under.
    #[must_use]
    pub fn terms(self) -> TermsHash {
        match self {
            Self::Basic { terms } | Self::Agreement { terms, .. } => terms,
            Self::Timeout { terms }
            | Self::ClaimantWins { terms, .. }
            | Self::ChallengerWins { terms, .. } => terms.hash(),
        }
    }

    /// Returns the deterministic resource cost of checking this proof.
    #[must_use]
    pub const fn cost(self) -> Cost {
        Cost::new(0, 0, 0, self.kind().proofs())
    }

    fn accepts(self, context: Context, resolve: &Resolve, edge: Edge) -> bool {
        match self {
            Self::Basic { terms } => terms == edge.terms(),
            Self::Agreement { terms, agreement } => {
                terms == edge.terms()
                    && agreement.accepts(edge.parties(), resolve.hash(ResolveKind::Agreement))
            }
            Self::Timeout { terms } => {
                terms.hash() == edge.terms() && context.block_height() >= terms.timeout()
            }
            Self::ClaimantWins { terms, seal } => {
                let kind = ResolveKind::ClaimantWins;
                terms.hash() == edge.terms()
                    && seal.accepts(terms.protocol(), kind, resolve.hash(kind))
            }
            Self::ChallengerWins { terms, seal } => {
                let kind = ResolveKind::ChallengerWins;
                terms.hash() == edge.terms()
                    && seal.accepts(terms.protocol(), kind, resolve.hash(kind))
            }
        }
    }
}

fn units(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn overlaps<T: Eq, const A: usize, const B: usize>(left: &List<T, A>, right: &List<T, B>) -> bool {
    for item in left.as_slice() {
        for other in right.as_slice() {
            if item == other {
                return true;
            }
        }
    }

    false
}

const fn empty_coins<const N: usize>() -> List<CoinId, N> {
    let fill = CoinId::from_bytes([0; CoinId::LENGTH]);
    let Some(ids) = List::new([fill; N], 0) else {
        return List::all([fill; N]);
    };
    ids
}

const fn empty_edges() -> EdgeList {
    let fill = EdgeId::from_bytes([0; EdgeId::LENGTH]);
    let Some(ids) = List::new([fill], 0) else {
        return List::all([fill]);
    };
    ids
}

const fn one_edge(id: EdgeId) -> EdgeList {
    let Some(ids) = List::new([id], 1) else {
        return List::all([id]);
    };
    ids
}

/// Coin payout requested by an edge resolve.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Payout {
    owner: Key,
    value: u64,
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
