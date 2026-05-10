//! Random operation sequences against a Rust reference model.
//!
//! This test runs `proptest-state-machine` over a closed enum of kernel
//! operations, applies each to both the kernel and a `BTreeMap`-backed
//! reference, and asserts the two agree on live coin/edge shape after every
//! step. The reference encodes the intended semantics in straight Rust, no
//! signatures and no fee math, so divergence from the kernel surfaces as a
//! bug in either side.
//!
//! Existing coverage:
//!   - `tests/sequence.rs`     — proptest with invariant checks (no ref).
//!   - `tests/itf.rs`          — Quint-driven trace replay (4 fixtures).
//!   - `tests/stateright.rs`   — exhaustive bounded model checking.
//!
//! What this adds: an *independent Rust reference* that proptest hammers with
//! random sequences (with shrinking) over a slightly different transition
//! grammar than Quint exposes, catching kernel-state-tracking bugs that
//! happen to lie outside Quint's transition relation.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, EdgeId, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS,
    Op, Open, Parties, Payout, Proof, ProtocolCode, Resolve, State, Terms,
};
use proptest::prelude::*;
use proptest::test_runner::Config;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use support::{FAKE_VERIFIER, FixedStore, party_one, payouts_two};

const COIN_SLOTS: usize = 6;
const EDGE_SLOTS: usize = 2;

const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));

const MAKER_COIN: CoinId = CoinId::from_bytes([1; CoinId::LENGTH]);
const TAKER_COIN: CoinId = CoinId::from_bytes([2; CoinId::LENGTH]);
const MAKER_VALUE: u64 = 10;
const TAKER_VALUE: u64 = 5;
const MAKER_PAYOUT: u64 = 7;
const TAKER_PAYOUT: u64 = 8;

const MAKER_SEED: Genesis = Genesis::coin(MAKER_COIN, MAKER, MAKER_VALUE);
const TAKER_SEED: Genesis = Genesis::coin(TAKER_COIN, TAKER, TAKER_VALUE);

// Reference model -----------------------------------------------------------

/// Live state, no fees, no signatures. The reference assumes every operation
/// it accepts the kernel will also accept; the kernel acceptance set is a
/// strict subset (proof verification, fee math, etc.). When the reference
/// applies a transition, the kernel must reach byte-identical live state.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct RefState {
    coins: BTreeMap<CoinId, RefCoin>,
    edges: BTreeMap<EdgeId, RefEdge>,
    height: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct RefCoin {
    owner: Key,
    value: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct RefEdge {
    value: u64,
}

impl RefState {
    fn genesis() -> Self {
        let mut coins = BTreeMap::new();
        coins.insert(
            MAKER_COIN,
            RefCoin {
                owner: MAKER,
                value: MAKER_VALUE,
            },
        );
        coins.insert(
            TAKER_COIN,
            RefCoin {
                owner: TAKER,
                value: TAKER_VALUE,
            },
        );
        Self {
            coins,
            edges: BTreeMap::new(),
            height: 1,
        }
    }
}

#[derive(Debug, Clone)]
enum Transition {
    /// Open the canonical full-funded edge (`MAKER_COIN`, `TAKER_COIN`) with
    /// the canonical timeout split as terms. Disabled once the edge is open.
    OpenFullEdge,
    /// Resolve the open edge with the canonical timeout payouts. Picks
    /// `Timeout` so the path requires no signatures and works in any feature
    /// config.
    ResolveTimeout,
    /// Advance height. Reaching `TIMEOUT` enables the resolve.
    Tick,
}

const fn terms() -> Terms {
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, canonical_payouts())
}

const fn canonical_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_two(MAKER, MAKER_PAYOUT, TAKER, TAKER_PAYOUT)
}

fn full_open() -> Open {
    Open::from_terms(
        Funding::new(party_one(MAKER_COIN), party_one(TAKER_COIN)),
        terms(),
    )
}

fn full_edge_id() -> EdgeId {
    full_open().output()
}

fn timeout_resolve() -> Resolve {
    Resolve::new(full_edge_id(), Proof::timeout(terms()), canonical_payouts())
}

struct L1Reference;

impl ReferenceStateMachine for L1Reference {
    type State = RefState;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(RefState::genesis()).boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let edge = full_edge_id();
        let edge_open = state.edges.contains_key(&edge);
        let funding_present =
            state.coins.contains_key(&MAKER_COIN) && state.coins.contains_key(&TAKER_COIN);

        // Each branch is gated on whether its precondition holds. Branches
        // contribute equal weight; proptest filters via `preconditions_met`.
        prop_oneof![
            Just(Transition::Tick),
            Just(if funding_present && !edge_open {
                Transition::OpenFullEdge
            } else {
                Transition::Tick
            }),
            Just(if edge_open && state.height >= TIMEOUT.get() {
                Transition::ResolveTimeout
            } else {
                Transition::Tick
            },),
        ]
        .boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Transition::OpenFullEdge => {
                let maker = state
                    .coins
                    .remove(&MAKER_COIN)
                    .expect("OpenFullEdge precondition: maker coin present");
                let taker = state
                    .coins
                    .remove(&TAKER_COIN)
                    .expect("OpenFullEdge precondition: taker coin present");
                let edge = full_edge_id();
                state.edges.insert(
                    edge,
                    RefEdge {
                        value: maker.value + taker.value,
                    },
                );
            }
            Transition::ResolveTimeout => {
                let edge = full_edge_id();
                state
                    .edges
                    .remove(&edge)
                    .expect("ResolveTimeout precondition: edge open");
                let resolve = timeout_resolve();
                let outputs = resolve.outputs();
                for (index, payout) in outputs.iter().enumerate() {
                    let id = payout.id(edge, index);
                    state.coins.insert(
                        id,
                        RefCoin {
                            owner: payout.owner(),
                            value: payout.value(),
                        },
                    );
                }
            }
            Transition::Tick => {
                state.height += 1;
            }
        }
        state
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            Transition::OpenFullEdge => {
                let edge = full_edge_id();
                !state.edges.contains_key(&edge)
                    && state.coins.contains_key(&MAKER_COIN)
                    && state.coins.contains_key(&TAKER_COIN)
            }
            Transition::ResolveTimeout => {
                let edge = full_edge_id();
                state.edges.contains_key(&edge) && state.height >= TIMEOUT.get()
            }
            Transition::Tick => true,
        }
    }
}

// SUT -----------------------------------------------------------------------

type Store = FixedStore<COIN_SLOTS, EDGE_SLOTS>;

struct Sut {
    state: State<Store>,
    /// Tracks block height under proptest control. The kernel reads height
    /// from each `Context`, so we synthesize the right context for resolves.
    height: u64,
}

struct L1Test;

impl StateMachineTest for L1Test {
    type SystemUnderTest = Sut;
    type Reference = L1Reference;

    fn init_test(
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        let outputs = canonical_payouts();
        let maker_out = outputs.as_slice()[0].id(full_edge_id(), 0);
        let taker_out = outputs.as_slice()[1].id(full_edge_id(), 1);
        let store = FixedStore::empty(
            [
                MAKER_COIN, TAKER_COIN, maker_out, taker_out, MAKER_COIN, TAKER_COIN,
            ],
            [full_edge_id(), full_edge_id()],
        );
        let state = State::genesis(store, &[MAKER_SEED, TAKER_SEED])
            .expect("genesis seeded against the canonical store");
        Sut { state, height: 1 }
    }

    fn apply(
        mut sut: Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        match transition {
            Transition::OpenFullEdge => {
                sut.state
                    .apply(CONTEXT, &FAKE_VERIFIER, &Op::Open(full_open()))
                    .expect("kernel rejected OpenFullEdge that ref accepted");
            }
            Transition::ResolveTimeout => {
                sut.state
                    .apply(
                        TIMEOUT_CONTEXT,
                        &FAKE_VERIFIER,
                        &Op::Resolve(timeout_resolve()),
                    )
                    .expect("kernel rejected ResolveTimeout that ref accepted");
            }
            Transition::Tick => {
                sut.height += 1;
            }
        }
        sut
    }

    fn check_invariants(
        sut: &Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        // Live coin set + values match.
        assert_eq!(
            sut.height, ref_state.height,
            "height: kernel {} vs ref {}",
            sut.height, ref_state.height,
        );
        for (id, ref_coin) in &ref_state.coins {
            let actual = sut.state.store().coin(*id).unwrap_or_else(|| {
                panic!("kernel missing coin {id:?} that ref expects {ref_coin:?}")
            });
            assert_eq!(actual.owner(), ref_coin.owner, "coin {id:?} owner");
            assert_eq!(actual.value(), ref_coin.value, "coin {id:?} value");
        }
        // Live edge set + values match.
        for (id, ref_edge) in &ref_state.edges {
            let actual = sut.state.store().edge(*id).unwrap_or_else(|| {
                panic!("kernel missing edge {id:?} that ref expects {ref_edge:?}")
            });
            assert_eq!(actual.value(), ref_edge.value, "edge {id:?} value");
        }
    }
}

prop_state_machine! {
    #![proptest_config(Config {
        cases: 64,
        max_shrink_iters: 256,
        ..Config::default()
    })]

    #[test]
    fn random_op_sequences_match_reference(sequential 1..32 => L1Test);
}
