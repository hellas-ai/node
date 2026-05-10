//! Generated multi-step operation sequence tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_core)]

mod support;

use support::{FixedStore, coin_id, state};

use hellas_kernel::{
    Agreement, BlockHash, BlockHeight, CoinId, Context, EdgeId, EventKind, Funding, Genesis, Key,
    List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties, Payout, Proof, ProtocolCode,
    Resolve, ResolveHash, ResolveKind, Seal, Sig, State, Terms, View,
};
use proptest::{
    collection::vec,
    prelude::{Strategy, prop_assert, prop_assert_eq, proptest},
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
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
const OTHER_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
const TERMS: Terms = Terms::basic(PROTOCOL, PARTIES, TIMEOUT);
const OTHER_TERMS: Terms = Terms::basic(OTHER_PROTOCOL, PARTIES, TIMEOUT);
const MAKER_ID: CoinId = coin_id(1);
const TAKER_ID: CoinId = coin_id(2);
const MAKER_VALUE: u64 = 10;
const TAKER_VALUE: u64 = 5;
const TOTAL: u64 = MAKER_VALUE + TAKER_VALUE;
const MAKER_PAYOUT: u64 = 7;
const TAKER_PAYOUT: u64 = 8;
const BAD_PAYOUT: u64 = 9;
const MAX_STEPS: usize = 16;

type TestState = State<FixedStore<6, 2>>;
type TestView = View<6, 2>;

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
    EarlyTimeout,
    Claimant,
    Challenger,
    WrongTerms,
    BadSeal,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Step {
    Open(EdgeKey),
    Resolve(EdgeKey, ProofKey),
    BadPayout(EdgeKey),
}

impl Step {
    const fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Open(EdgeKey::First),
            1 => Self::Open(EdgeKey::Second),
            2 => Self::Resolve(EdgeKey::First, ProofKey::Basic),
            3 => Self::Resolve(EdgeKey::Second, ProofKey::Basic),
            4 => Self::Resolve(EdgeKey::First, ProofKey::Agreement),
            5 => Self::Resolve(EdgeKey::Second, ProofKey::Agreement),
            6 => Self::Resolve(EdgeKey::First, ProofKey::Timeout),
            7 => Self::Resolve(EdgeKey::Second, ProofKey::Timeout),
            8 => Self::Resolve(EdgeKey::First, ProofKey::EarlyTimeout),
            9 => Self::Resolve(EdgeKey::Second, ProofKey::EarlyTimeout),
            10 => Self::Resolve(EdgeKey::First, ProofKey::Claimant),
            11 => Self::Resolve(EdgeKey::Second, ProofKey::Challenger),
            12 => Self::Resolve(EdgeKey::First, ProofKey::WrongTerms),
            13 => Self::Resolve(EdgeKey::Second, ProofKey::BadSeal),
            14 => Self::BadPayout(EdgeKey::First),
            _ => Self::BadPayout(EdgeKey::Second),
        }
    }

    const fn context(self) -> Context {
        match self {
            Self::Resolve(_, ProofKey::Timeout) => TIMEOUT_CONTEXT,
            _ => CONTEXT,
        }
    }

    fn op(self) -> Op {
        match self {
            Self::Open(edge) => Op::Open(open(edge)),
            Self::Resolve(edge, proof) => Op::Resolve(resolve(edge, proof, payouts())),
            Self::BadPayout(edge) => Op::Resolve(resolve(edge, ProofKey::Basic, bad_payouts())),
        }
    }
}

proptest! {
    #[test]
    fn generated_operation_sequences_conserve_value(steps in vec(step(), 0..=MAX_STEPS)) {
        let mut state = initial_state();

        assert_invariants(&state)?;
        for step in steps {
            let before = state;
            let op = step.op();
            let result = state.apply(step.context(), &op);

            if result.is_err() {
                prop_assert_eq!(state, before);
            }
            if let Ok(event) = result {
                assert_event_matches(step, &event.kind())?;
            }
            assert_invariants(&state)?;
        }
    }
}

fn step() -> impl Strategy<Value = Step> {
    (0_u8..=15).prop_map(Step::from_index)
}

fn assert_invariants(state: &TestState) -> Result<(), proptest::test_runner::TestCaseError> {
    let view: TestView = state.view();

    prop_assert_eq!(live_value(&view), TOTAL);
    prop_assert!(view.edge_len() <= 1);
    for (_, edge) in view.edges() {
        prop_assert_eq!(edge.parties(), PARTIES);
        prop_assert_eq!(edge.terms(), TERMS.hash());
    }

    Ok(())
}

fn assert_event_matches(
    step: Step,
    event: &EventKind,
) -> Result<(), proptest::test_runner::TestCaseError> {
    match (step, event) {
        (Step::Open(edge), EventKind::EdgeOpened { output, .. }) => {
            prop_assert_eq!(*output, edge_id(edge));
        }
        (Step::Resolve(edge, proof), EventKind::EdgeResolved { input, outputs })
            if proof != ProofKey::EarlyTimeout
                && proof != ProofKey::WrongTerms
                && proof != ProofKey::BadSeal =>
        {
            prop_assert_eq!(*input, edge_id(edge));
            prop_assert_eq!(*outputs, output_ids(edge));
        }
        (Step::BadPayout(edge), EventKind::EdgeResolved { input, outputs }) => {
            prop_assert_eq!(*input, edge_id(edge));
            prop_assert_eq!(*outputs, output_ids(edge));
        }
        _ => prop_assert!(false),
    }

    Ok(())
}

fn live_value(view: &TestView) -> u64 {
    let mut total = 0_u64;
    for (_, coin) in view.coins() {
        total = total.saturating_add(coin.value());
    }
    for (_, edge) in view.edges() {
        total = total.saturating_add(edge.value());
    }
    total
}

fn initial_state() -> TestState {
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

fn resolve(edge: EdgeKey, proof: ProofKey, outputs: List<Payout, MAX_EDGE_OUTPUTS>) -> Resolve {
    Resolve::new(edge_id(edge), proof_for(edge, proof, &outputs), outputs)
}

fn proof_for(edge: EdgeKey, proof: ProofKey, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    match proof {
        ProofKey::Basic => Proof::basic(TERMS.hash()),
        ProofKey::Agreement => Proof::agreement(
            TERMS.hash(),
            Agreement::new(
                Sig::placeholder(MAKER, hash(edge, ResolveKind::Agreement, outputs)),
                Sig::placeholder(TAKER, hash(edge, ResolveKind::Agreement, outputs)),
            ),
        ),
        ProofKey::Timeout | ProofKey::EarlyTimeout => Proof::timeout(TERMS),
        ProofKey::Claimant => {
            Proof::claimant_wins(TERMS, seal(edge, ResolveKind::ClaimantWins, outputs))
        }
        ProofKey::Challenger => {
            Proof::challenger_wins(TERMS, seal(edge, ResolveKind::ChallengerWins, outputs))
        }
        ProofKey::WrongTerms => Proof::basic(OTHER_TERMS.hash()),
        ProofKey::BadSeal => {
            Proof::claimant_wins(TERMS, seal(edge, ResolveKind::ChallengerWins, outputs))
        }
    }
}

fn seal(edge: EdgeKey, kind: ResolveKind, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    Seal::placeholder(PROTOCOL, kind, hash(edge, kind, outputs))
}

fn hash(edge: EdgeKey, kind: ResolveKind, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> ResolveHash {
    Resolve::payload_hash(edge_id(edge), kind, TERMS.hash(), outputs)
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
    payout_list(MAKER_PAYOUT, TAKER_PAYOUT)
}

fn bad_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payout_list(MAKER_PAYOUT, BAD_PAYOUT)
}

fn payout_list(maker: u64, taker: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new(
        [
            Payout::new(MAKER, maker),
            Payout::new(TAKER, taker),
            Payout::new(MAKER, maker),
            Payout::new(MAKER, maker),
        ],
        2,
    ) else {
        panic!("invalid generated payout list");
    };
    outputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid generated party list");
    };
    inputs
}

fn nth<const N: usize>(ids: List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}
