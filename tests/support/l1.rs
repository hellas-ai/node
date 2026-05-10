#![allow(dead_code)]

use super::{FixedStore, coin_id, state};

use hellas_kernel::{
    Agreement, BlockHash, BlockHeight, CoinId, Context, Edge, EdgeId, EventKind, Funding, Genesis,
    Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties, Payout, Proof, ProtocolCode,
    Resolve, ResolveHash, ResolveKind, Seal, Sig, State, Terms, View,
};

pub(crate) const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
pub(crate) const TIMEOUT: BlockHeight = BlockHeight::new(2);
pub(crate) const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));
pub(crate) const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
pub(crate) const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
pub(crate) const PARTIES: Parties = Parties::new(MAKER, TAKER);
pub(crate) const TERMS: Terms = Terms::basic(ProtocolCode::new(1), PARTIES, TIMEOUT);
pub(crate) const MAKER_ID: CoinId = coin_id(1);
pub(crate) const TAKER_ID: CoinId = coin_id(2);
pub(crate) const MAKER_VALUE: u64 = 10;
pub(crate) const TAKER_VALUE: u64 = 5;
pub(crate) const EDGE_VALUE: u64 = MAKER_VALUE + TAKER_VALUE;
pub(crate) const MAKER_PAYOUT: u64 = 7;
pub(crate) const TAKER_PAYOUT: u64 = 8;

pub(crate) type TraceState = State<FixedStore<6, 2>>;
pub(crate) type TraceView = View<6, 2>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum Step {
    Open(EdgeKey),
    Resolve(EdgeKey, ProofKey),
    Tick,
}

impl Step {
    pub(crate) const fn context(self) -> Context {
        match self {
            Self::Resolve(_, ProofKey::Timeout) => TIMEOUT_CONTEXT,
            _ => CONTEXT,
        }
    }

    pub(crate) fn op(self) -> Option<Op> {
        match self {
            Self::Open(edge) => Some(Op::Open(open(edge))),
            Self::Resolve(edge, proof) => Some(Op::Resolve(resolve(edge, proof))),
            Self::Tick => None,
        }
    }

    pub(crate) fn check(self, event: &EventKind) {
        match (self, event) {
            (Self::Open(edge), EventKind::EdgeOpened { output, .. }) => {
                assert_eq!(*output, edge_id(edge));
            }
            (Self::Resolve(edge, _), EventKind::EdgeResolved { input, outputs }) => {
                assert_eq!(*input, edge_id(edge));
                assert_eq!(*outputs, output_ids(edge));
            }
            _ => panic!("trace event mismatch"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum EdgeKey {
    First,
    Second,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum ProofKey {
    Basic,
    Agreement,
    Timeout,
    Claimant,
    Challenger,
    EarlyTimeout,
}

pub(crate) fn initial_state() -> TraceState {
    state(
        FixedStore::empty(
            [
                MAKER_ID,
                TAKER_ID,
                maker_out(EdgeKey::First),
                taker_out(EdgeKey::First),
                maker_out(EdgeKey::Second),
                taker_out(EdgeKey::Second),
            ],
            [edge_id(EdgeKey::First), edge_id(EdgeKey::Second)],
        ),
        [
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    )
}

pub(crate) fn open(edge: EdgeKey) -> Open {
    match edge {
        EdgeKey::First => Open::from_terms(Funding::new(party1(MAKER_ID), party1(TAKER_ID)), TERMS),
        EdgeKey::Second => Open::from_terms(
            Funding::new(
                party1(maker_out(EdgeKey::First)),
                party1(taker_out(EdgeKey::First)),
            ),
            TERMS,
        ),
    }
}

pub(crate) fn resolve(edge: EdgeKey, proof: ProofKey) -> Resolve {
    Resolve::new(edge_id(edge), proof_for(edge, proof), payouts())
}

pub(crate) fn edge_id(edge: EdgeKey) -> EdgeId {
    open(edge).output()
}

pub(crate) fn maker_out(edge: EdgeKey) -> CoinId {
    nth(output_ids(edge), 0)
}

pub(crate) fn taker_out(edge: EdgeKey) -> CoinId {
    nth(output_ids(edge), 1)
}

pub(crate) fn output_ids(edge: EdgeKey) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Resolve::new(edge_id(edge), Proof::basic(TERMS.hash()), payouts()).output_ids()
}

pub(crate) const fn edge_value(edge: Edge) -> u64 {
    edge.value()
}

fn proof_for(edge: EdgeKey, proof: ProofKey) -> Proof {
    match proof {
        ProofKey::Basic => Proof::basic(TERMS.hash()),
        ProofKey::Agreement => Proof::agreement(
            TERMS.hash(),
            Agreement::new(
                Sig::placeholder(MAKER, hash(edge, ResolveKind::Agreement)),
                Sig::placeholder(TAKER, hash(edge, ResolveKind::Agreement)),
            ),
        ),
        ProofKey::Timeout | ProofKey::EarlyTimeout => Proof::timeout(TERMS),
        ProofKey::Claimant => Proof::claimant_wins(TERMS, seal(edge, ResolveKind::ClaimantWins)),
        ProofKey::Challenger => {
            Proof::challenger_wins(TERMS, seal(edge, ResolveKind::ChallengerWins))
        }
    }
}

fn seal(edge: EdgeKey, kind: ResolveKind) -> Seal {
    Seal::placeholder(TERMS.protocol(), kind, hash(edge, kind))
}

fn hash(edge: EdgeKey, kind: ResolveKind) -> ResolveHash {
    Resolve::payload_hash(edge_id(edge), kind, TERMS.hash(), &payouts())
}

fn payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new(
        [
            Payout::new(MAKER, MAKER_PAYOUT),
            Payout::new(TAKER, TAKER_PAYOUT),
            Payout::new(MAKER, MAKER_PAYOUT),
            Payout::new(MAKER, MAKER_PAYOUT),
        ],
        2,
    ) else {
        panic!("invalid trace payout list");
    };
    outputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid trace party list");
    };
    inputs
}

fn nth<const N: usize>(ids: List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}
