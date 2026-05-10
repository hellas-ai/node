#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

//! ITF fixture replay against concrete Rust state.
//!
//! Quint emits each abstract trace as an `Informal Trace Format` JSON file
//! (see `models/traces/`). Deserialization uses the upstream `itf` crate
//! (Cosmos/Malachite ecosystem standard) so that variable shapes — Quint maps,
//! sets, and bigints — translate into Rust types without hand-rolled parsing.
//! Each test specifies the operation sequence that produced the trace; the
//! runner replays it against the kernel and asserts that live coin/edge
//! shape and height match the abstract state at every step.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use itf::de::{As, Integer, Same};
use serde::Deserialize;
use support::{
    FAKE_VERIFIER, coin_view,
    l1::{
        EdgeKey, MAKER, MAKER_ID, ProofKey, Step, TAKER, TAKER_ID, TraceState, TraceView, edge_id,
        edge_value, initial_state, maker_out, taker_out,
    },
};

/// Abstract state mirrored from `models/l1.qnt`. Variable order and names
/// must match the Quint declarations exactly; the `itf` crate verifies the
/// trace's variable list against the struct's fields at parse time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    coins: BTreeMap<CoinTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    edges: BTreeMap<EdgeTag, i64>,
    #[serde(with = "As::<Integer>")]
    height: i64,
    live_coins: BTreeSet<CoinTag>,
    live_edges: BTreeSet<EdgeTag>,
}

/// Tags mirror the Quint `Coin` enum's variant names. The `tag`/`content`
/// adapter matches Quint's internally-tagged enum encoding
/// (`{"tag": "MakerCoin", "value": {"#tup": []}}`).
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum CoinTag {
    MakerCoin,
    TakerCoin,
    MakerOut1,
    TakerOut1,
    MakerOut2,
    TakerOut2,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum EdgeTag {
    Edge1,
    Edge2,
}

#[derive(Debug, Clone, Copy)]
struct Fixture<const N: usize> {
    name: &'static str,
    json: &'static str,
    steps: [Step; N],
}

impl<const N: usize> Fixture<N> {
    const fn new(name: &'static str, json: &'static str, steps: [Step; N]) -> Self {
        Self { name, json, steps }
    }

    fn replay(&self) {
        let trace = match itf::trace_from_str::<State>(self.json) {
            Ok(trace) => trace,
            Err(error) => panic!("invalid ITF fixture {}: {error}", self.name),
        };
        assert_eq!(
            trace.states.len(),
            self.steps.len() + 1,
            "{}: states={}, steps={}",
            self.name,
            trace.states.len(),
            self.steps.len(),
        );

        let mut state = initial_state();
        let mut height = 1_i64;
        self.check(&state, &trace.states[0].value, height);

        for (index, step) in self.steps.into_iter().enumerate() {
            if step == Step::Tick {
                height += 1;
            } else {
                let Some(op) = step.op() else {
                    panic!("fixture step has no operation");
                };
                let Ok(event) = state.apply(step.context(), &FAKE_VERIFIER, &op) else {
                    panic!("fixture operation rejected");
                };
                step.check(&event.kind());
            }

            self.check(&state, &trace.states[index + 1].value, height);
        }
    }

    fn check(&self, state: &TraceState, expected: &State, height: i64) {
        let view: TraceView = state.view();

        assert_eq!(expected.height, height, "{}", self.name);
        assert_eq!(view.coin_len(), expected.live_coins.len(), "{}", self.name);
        assert_eq!(view.edge_len(), expected.live_edges.len(), "{}", self.name);
        check_coin(expected, &view, CoinTag::MakerCoin, MAKER_ID, MAKER);
        check_coin(expected, &view, CoinTag::TakerCoin, TAKER_ID, TAKER);
        check_coin(
            expected,
            &view,
            CoinTag::MakerOut1,
            maker_out(EdgeKey::First),
            MAKER,
        );
        check_coin(
            expected,
            &view,
            CoinTag::TakerOut1,
            taker_out(EdgeKey::First),
            TAKER,
        );
        check_coin(
            expected,
            &view,
            CoinTag::MakerOut2,
            maker_out(EdgeKey::Second),
            MAKER,
        );
        check_coin(
            expected,
            &view,
            CoinTag::TakerOut2,
            taker_out(EdgeKey::Second),
            TAKER,
        );
        check_edge(expected, &view, EdgeTag::Edge1, edge_id(EdgeKey::First));
        check_edge(expected, &view, EdgeTag::Edge2, edge_id(EdgeKey::Second));
    }
}

#[test]
fn replays_basic_itf() {
    Fixture::new(
        "basicTraceTest",
        include_str!("../models/traces/l1_basicTraceTest.itf.json"),
        [
            Step::Open(EdgeKey::First),
            Step::Resolve(EdgeKey::First, ProofKey::Timeout),
        ],
    )
    .replay();
}

#[test]
#[cfg(feature = "fake-crypto")]
fn replays_agreement_timeout_itf() {
    Fixture::new(
        "agreementTimeoutTraceTest",
        include_str!("../models/traces/l1_agreementTimeoutTraceTest.itf.json"),
        [
            Step::Open(EdgeKey::First),
            Step::Resolve(EdgeKey::First, ProofKey::Agreement),
            Step::Open(EdgeKey::Second),
            Step::Tick,
            Step::Resolve(EdgeKey::Second, ProofKey::Timeout),
        ],
    )
    .replay();
}

#[test]
#[cfg(feature = "fake-crypto")]
fn replays_dispute_itf() {
    Fixture::new(
        "disputeTraceTest",
        include_str!("../models/traces/l1_disputeTraceTest.itf.json"),
        [
            Step::Open(EdgeKey::First),
            Step::Resolve(EdgeKey::First, ProofKey::Claimant),
            Step::Open(EdgeKey::Second),
            Step::Resolve(EdgeKey::Second, ProofKey::Challenger),
        ],
    )
    .replay();
}

#[test]
fn replays_early_timeout_guard_itf() {
    Fixture::new(
        "earlyTimeoutRejectedTest",
        include_str!("../models/traces/l1_earlyTimeoutRejectedTest.itf.json"),
        [Step::Open(EdgeKey::First)],
    )
    .replay();
}

fn check_coin(
    expected: &State,
    view: &TraceView,
    tag: CoinTag,
    id: hellas_kernel::CoinId,
    owner: hellas_kernel::Key,
) {
    let coin = view.coin(id).map(coin_view);

    if expected.live_coins.contains(&tag) {
        let value = expected
            .coins
            .get(&tag)
            .copied()
            .map(u64::try_from)
            .and_then(Result::ok)
            .unwrap_or_else(|| panic!("missing or negative coin value: {tag:?}"));
        assert_eq!(coin, Some((owner, value)), "{tag:?}");
        return;
    }

    assert_eq!(coin, None, "{tag:?}");
}

fn check_edge(expected: &State, view: &TraceView, tag: EdgeTag, id: hellas_kernel::EdgeId) {
    let live = expected.live_edges.contains(&tag);

    if live {
        let value = expected
            .edges
            .get(&tag)
            .copied()
            .map(u64::try_from)
            .and_then(Result::ok)
            .unwrap_or_else(|| panic!("missing or negative edge value: {tag:?}"));
        assert_eq!(view.edge(id).map(edge_value), Some(value), "{tag:?}");
    } else {
        assert_eq!(view.edge(id), None, "{tag:?}");
    }
}
