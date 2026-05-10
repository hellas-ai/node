//! Replay checks for abstract model traces against concrete Rust state.

mod support;

use support::{FixedStore, coin_id, coin_view, state};

use hellas_kernel::{
    Agreement, ApplyError, BlockHash, BlockHeight, CoinId, Context, Edge, EdgeId, EventKind,
    Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties, Payout,
    Proof, ProtocolCode, Resolve, ResolveHash, ResolveKind, Seal, Sig, State, Terms, View,
};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));
const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const TERMS: Terms = Terms::basic(ProtocolCode::new(1), PARTIES, TIMEOUT);
const MAKER_ID: CoinId = coin_id(1);
const TAKER_ID: CoinId = coin_id(2);
const MAKER_VALUE: u64 = 10;
const TAKER_VALUE: u64 = 5;
const MAKER_PAYOUT: u64 = 7;
const TAKER_PAYOUT: u64 = 8;

type TraceState = State<FixedStore<6, 2>>;
type TraceView = View<6, 2>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct Trace<const N: usize> {
    frames: [Frame; N],
}

impl<const N: usize> Trace<N> {
    const fn new(frames: [Frame; N]) -> Self {
        Self { frames }
    }

    fn replay(&self) {
        let mut state = initial_state();

        Shape::Genesis.check(&state);
        for frame in self.frames {
            frame.replay(&mut state);
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct Frame {
    mov: Move,
    out: Out,
}

impl Frame {
    const fn accept(mov: Move, shape: Shape) -> Self {
        Self {
            mov,
            out: Out::Accept(shape),
        }
    }

    const fn reject(mov: Move, error: ApplyError, shape: Shape) -> Self {
        Self {
            mov,
            out: Out::Reject(error, shape),
        }
    }

    fn replay(self, state: &mut TraceState) {
        let op = self.mov.op();

        match self.out {
            Out::Accept(shape) => {
                let Ok(event) = state.apply(self.mov.context(), &op) else {
                    panic!("trace move rejected");
                };
                self.mov.check(&event.kind());
                shape.check(state);
            }
            Out::Reject(error, shape) => {
                let before = *state;
                assert_eq!(state.apply(self.mov.context(), &op), Err(error));
                assert_eq!(*state, before);
                shape.check(state);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Out {
    Accept(Shape),
    Reject(ApplyError, Shape),
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Shape {
    Genesis,
    Edge(EdgeKey),
    Payout(EdgeKey),
}

impl Shape {
    fn check(self, state: &TraceState) {
        let view: TraceView = state.view();

        match self {
            Self::Genesis => {
                assert_eq!(view.coin_len(), 2);
                assert_eq!(view.edge_len(), 0);
                assert_eq!(
                    view.coin(MAKER_ID).map(coin_view),
                    Some((MAKER, MAKER_VALUE)),
                );
                assert_eq!(
                    view.coin(TAKER_ID).map(coin_view),
                    Some((TAKER, TAKER_VALUE)),
                );
            }
            Self::Edge(edge) => {
                assert_eq!(view.coin_len(), 0);
                assert_eq!(view.edge_len(), 1);
                assert_eq!(view.edge(edge_id(edge)).map(edge_view), Some(15));
            }
            Self::Payout(edge) => {
                assert_eq!(view.coin_len(), 2);
                assert_eq!(view.edge_len(), 0);
                assert_eq!(
                    view.coin(maker_out(edge)).map(coin_view),
                    Some((MAKER, MAKER_PAYOUT)),
                );
                assert_eq!(
                    view.coin(taker_out(edge)).map(coin_view),
                    Some((TAKER, TAKER_PAYOUT)),
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Move {
    Open(EdgeKey),
    Resolve(EdgeKey, ProofKey),
}

impl Move {
    const fn context(self) -> Context {
        match self {
            Self::Resolve(_, ProofKey::Timeout) => TIMEOUT_CONTEXT,
            _ => CONTEXT,
        }
    }

    fn op(self) -> Op {
        match self {
            Self::Open(edge) => Op::Open(open(edge)),
            Self::Resolve(edge, proof) => Op::Resolve(resolve(edge, proof)),
        }
    }

    fn check(self, event: &EventKind) {
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
enum EdgeKey {
    First,
    Second,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum ProofKey {
    Basic,
    Agreement,
    Timeout,
    Claimant,
    Challenger,
    EarlyTimeout,
}

#[test]
fn replays_basic_trace() {
    Trace::new([
        Frame::accept(Move::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Move::Resolve(EdgeKey::First, ProofKey::Basic),
            Shape::Payout(EdgeKey::First),
        ),
    ])
    .replay();
}

#[test]
fn replays_agreement_then_timeout_trace() {
    Trace::new([
        Frame::accept(Move::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Move::Resolve(EdgeKey::First, ProofKey::Agreement),
            Shape::Payout(EdgeKey::First),
        ),
        Frame::accept(Move::Open(EdgeKey::Second), Shape::Edge(EdgeKey::Second)),
        Frame::accept(
            Move::Resolve(EdgeKey::Second, ProofKey::Timeout),
            Shape::Payout(EdgeKey::Second),
        ),
    ])
    .replay();
}

#[test]
fn replays_dispute_outcome_trace() {
    Trace::new([
        Frame::accept(Move::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Move::Resolve(EdgeKey::First, ProofKey::Claimant),
            Shape::Payout(EdgeKey::First),
        ),
        Frame::accept(Move::Open(EdgeKey::Second), Shape::Edge(EdgeKey::Second)),
        Frame::accept(
            Move::Resolve(EdgeKey::Second, ProofKey::Challenger),
            Shape::Payout(EdgeKey::Second),
        ),
    ])
    .replay();
}

#[test]
fn replays_rejected_trace_step_without_mutation() {
    Trace::new([
        Frame::accept(Move::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::reject(
            Move::Resolve(EdgeKey::First, ProofKey::EarlyTimeout),
            ApplyError::InvalidProof {
                input: edge_id(EdgeKey::First),
            },
            Shape::Edge(EdgeKey::First),
        ),
        Frame::accept(
            Move::Resolve(EdgeKey::First, ProofKey::Timeout),
            Shape::Payout(EdgeKey::First),
        ),
    ])
    .replay();
}

fn initial_state() -> TraceState {
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

fn open(edge: EdgeKey) -> Open {
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

fn resolve(edge: EdgeKey, proof: ProofKey) -> Resolve {
    Resolve::new(edge_id(edge), proof_for(edge, proof), payouts())
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

fn edge_id(edge: EdgeKey) -> EdgeId {
    open(edge).output()
}

fn maker_out(edge: EdgeKey) -> CoinId {
    nth(output_ids(edge), 0)
}

fn taker_out(edge: EdgeKey) -> CoinId {
    nth(output_ids(edge), 1)
}

fn output_ids(edge: EdgeKey) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Resolve::new(edge_id(edge), Proof::basic(TERMS.hash()), payouts()).output_ids()
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

const fn edge_view(edge: Edge) -> u64 {
    edge.value()
}
