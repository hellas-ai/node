//! Static-wave equivalence checks for declared access sets.

mod support;

use support::{FAKE_VERIFIER, FixedStore, coin_id, state};

use hellas_kernel::{
    Block, BlockHash, BlockHeight, CoinId, Context, EdgeId, Funding, Genesis, Key, List,
    MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties, Payout, Proof, ProtocolCode, Resolve,
    State, Terms, View,
};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT: BlockHeight = BlockHeight::new(1);
const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const A_MAKER: CoinId = coin_id(1);
const A_TAKER: CoinId = coin_id(2);
const B_MAKER: CoinId = coin_id(3);
const B_TAKER: CoinId = coin_id(4);
const MAKER_VALUE: u64 = 10;
const TAKER_VALUE: u64 = 5;
const MAKER_PAYOUT: u64 = 7;
const TAKER_PAYOUT: u64 = 8;
const TIMEOUT_OUTPUTS: List<Payout, MAX_EDGE_OUTPUTS> = payouts_const(MAKER_PAYOUT, TAKER_PAYOUT);
const TERMS: Terms = Terms::basic(ProtocolCode::new(1), PARTIES, TIMEOUT, TIMEOUT_OUTPUTS);

type TestState = State<FixedStore<8, 2>>;
type TestView = View<8, 2>;
type Ops = List<Op, 4>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct Plan<const N: usize> {
    wave: [usize; N],
    len: usize,
}

impl<const N: usize> Plan<N> {
    fn build(ops: &List<Op, N>) -> Self {
        let mut plan = Self {
            wave: [0; N],
            len: 0,
        };
        let mut index = 0;

        while index < ops.len() {
            plan.place(ops, index);
            index += 1;
        }

        plan
    }

    const fn wave(&self, index: usize) -> Option<usize> {
        if index >= self.wave.len() {
            return None;
        }

        Some(self.wave[index])
    }

    fn place(&mut self, ops: &List<Op, N>, index: usize) {
        let mut wave = 0;

        while self.conflicts(ops, index, wave) {
            wave += 1;
        }

        self.wave[index] = wave;
        self.len = self.len.max(wave + 1);
    }

    fn conflicts(&self, ops: &List<Op, N>, index: usize, wave: usize) -> bool {
        let items = ops.as_slice();
        let mut prior = 0;

        while prior < index {
            if self.wave[prior] == wave && items[index].conflicts(&items[prior]) {
                return true;
            }
            prior += 1;
        }

        false
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum EdgeKey {
    A,
    B,
}

#[test]
fn disjoint_waves_match_ordered_block_transition() {
    let block = Block::new(CONTEXT, ops());
    let ops = block.ops();
    let plan = Plan::build(ops);
    let mut ordered = initial_state();
    let mut waved = initial_state();

    assert_eq!(plan.len, 2);
    assert_eq!(plan.wave(0), Some(0));
    assert_eq!(plan.wave(1), Some(0));
    assert_eq!(plan.wave(2), Some(1));
    assert_eq!(plan.wave(3), Some(1));
    assert!(!ops.as_slice()[0].conflicts(&ops.as_slice()[1]));
    assert!(!ops.as_slice()[2].conflicts(&ops.as_slice()[3]));
    assert!(ops.as_slice()[0].conflicts(&ops.as_slice()[2]));

    let Ok(diff) = ordered.apply_block(&FAKE_VERIFIER, &block) else {
        panic!("ordered block rejected");
    };
    apply_reversed_waves(&mut waved, ops, plan);

    let ordered_view: TestView = ordered.view();
    let waved_view: TestView = waved.view();

    assert_eq!(diff.len(), 4);
    assert_eq!(ordered_view, waved_view);
}

fn apply_reversed_waves(state: &mut TestState, ops: &Ops, plan: Plan<4>) {
    let mut wave = 0;

    while wave < plan.len {
        let mut index = ops.len();
        while index > 0 {
            index -= 1;
            if plan.wave(index) == Some(wave) {
                let Ok(_event) = state.apply(CONTEXT, &FAKE_VERIFIER, &ops.as_slice()[index])
                else {
                    panic!("wave operation rejected");
                };
            }
        }
        wave += 1;
    }
}

fn initial_state() -> TestState {
    state(
        FixedStore::empty(
            [
                A_MAKER,
                A_TAKER,
                B_MAKER,
                B_TAKER,
                maker_out(EdgeKey::A),
                taker_out(EdgeKey::A),
                maker_out(EdgeKey::B),
                taker_out(EdgeKey::B),
            ],
            [edge_id(EdgeKey::A), edge_id(EdgeKey::B)],
        ),
        [
            Genesis::coin(A_MAKER, MAKER, MAKER_VALUE),
            Genesis::coin(A_TAKER, TAKER, TAKER_VALUE),
            Genesis::coin(B_MAKER, MAKER, MAKER_VALUE),
            Genesis::coin(B_TAKER, TAKER, TAKER_VALUE),
        ],
    )
}

fn ops() -> Ops {
    List::all([
        Op::Open(open(EdgeKey::A)),
        Op::Open(open(EdgeKey::B)),
        Op::Resolve(resolve(EdgeKey::A)),
        Op::Resolve(resolve(EdgeKey::B)),
    ])
}

fn open(edge: EdgeKey) -> Open {
    let (maker, taker) = match edge {
        EdgeKey::A => (A_MAKER, A_TAKER),
        EdgeKey::B => (B_MAKER, B_TAKER),
    };

    Open::from_terms(Funding::new(party1(maker), party1(taker)), TERMS)
}

fn resolve(edge: EdgeKey) -> Resolve {
    Resolve::new(edge_id(edge), Proof::timeout(TERMS), payouts())
}

fn edge_id(edge: EdgeKey) -> EdgeId {
    open(edge).output()
}

fn maker_out(edge: EdgeKey) -> CoinId {
    output_ids(edge).as_slice()[0]
}

fn taker_out(edge: EdgeKey) -> CoinId {
    output_ids(edge).as_slice()[1]
}

fn output_ids(edge: EdgeKey) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Resolve::new(edge_id(edge), Proof::timeout(TERMS), payouts()).output_ids()
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
        panic!("invalid parallel payout list");
    };
    outputs
}

const fn payouts_const(maker: u64, taker: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new(
        [
            Payout::new(MAKER, maker),
            Payout::new(TAKER, taker),
            Payout::new(MAKER, maker),
            Payout::new(MAKER, maker),
        ],
        2,
    ) else {
        panic!("invalid parallel payout list");
    };
    outputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid parallel party list");
    };
    inputs
}
