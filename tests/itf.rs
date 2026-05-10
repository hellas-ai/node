#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

//! ITF fixture replay against concrete Rust state.

mod support;

use serde::Deserialize;

use support::{
    coin_view,
    l1::{
        EdgeKey, MAKER, MAKER_ID, ProofKey, Step, TAKER, TAKER_ID, TraceState, TraceView, edge_id,
        edge_value, initial_state, maker_out, taker_out,
    },
};

const VARS: [&str; 4] = ["coins", "edges", "height", "liveEdges"];

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
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
        let trace = ItfTrace::parse(self.name, self.json);
        assert_eq!(trace.states.len(), self.steps.len() + 1, "{}", self.name);

        let mut state = initial_state();
        let mut height = 1;
        self.check(&state, &trace.states[0], height);

        for (index, step) in self.steps.into_iter().enumerate() {
            if step == Step::Tick {
                height += 1;
            } else {
                let Some(op) = step.op() else {
                    panic!("fixture step has no operation");
                };
                let Ok(event) = state.apply(step.context(), &op) else {
                    panic!("fixture operation rejected");
                };
                step.check(&event.kind());
            }

            self.check(&state, &trace.states[index + 1], height);
        }
    }

    fn check(&self, state: &TraceState, expected: &ItfState, height: u64) {
        let view: TraceView = state.view();

        assert_eq!(expected.height.as_u64(), height, "{}", self.name);
        assert_eq!(view.coin_len(), expected.live_coins(), "{}", self.name);
        assert_eq!(view.edge_len(), expected.live_edges(), "{}", self.name);
        check_coin(expected, &view, "MakerCoin", MAKER_ID, MAKER);
        check_coin(expected, &view, "TakerCoin", TAKER_ID, TAKER);
        check_coin(
            expected,
            &view,
            "MakerOut1",
            maker_out(EdgeKey::First),
            MAKER,
        );
        check_coin(
            expected,
            &view,
            "TakerOut1",
            taker_out(EdgeKey::First),
            TAKER,
        );
        check_coin(
            expected,
            &view,
            "MakerOut2",
            maker_out(EdgeKey::Second),
            MAKER,
        );
        check_coin(
            expected,
            &view,
            "TakerOut2",
            taker_out(EdgeKey::Second),
            TAKER,
        );
        check_edge(expected, &view, "Edge1", edge_id(EdgeKey::First));
        check_edge(expected, &view, "Edge2", edge_id(EdgeKey::Second));
    }
}

#[test]
fn replays_basic_itf() {
    Fixture::new(
        "basicTraceTest",
        include_str!("../models/traces/l1_basicTraceTest.itf.json"),
        [
            Step::Open(EdgeKey::First),
            Step::Resolve(EdgeKey::First, ProofKey::Basic),
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
    expected: &ItfState,
    view: &TraceView,
    tag: &str,
    id: hellas_kernel::CoinId,
    owner: hellas_kernel::Key,
) {
    let value = expected.coins.get(tag);
    let live = view.coin(id).map(coin_view);

    if value == 0 {
        assert_eq!(live, None, "{tag}");
    } else {
        assert_eq!(live, Some((owner, value)), "{tag}");
    }
}

fn check_edge(expected: &ItfState, view: &TraceView, tag: &str, id: hellas_kernel::EdgeId) {
    let value = expected.edges.get(tag);
    let live = expected.live_edges.contains(tag);

    assert_eq!(live, value != 0, "{tag}");
    if live {
        assert_eq!(view.edge(id).map(edge_value), Some(value), "{tag}");
    } else {
        assert_eq!(view.edge(id), None, "{tag}");
    }
}

#[derive(Debug, Deserialize)]
struct ItfTrace {
    vars: Vec<String>,
    states: Vec<ItfState>,
}

impl ItfTrace {
    fn parse(name: &str, json: &str) -> Self {
        let Ok(trace) = serde_json::from_str::<Self>(json) else {
            panic!("invalid ITF fixture: {name}");
        };

        trace.check_vars(name);
        trace
    }

    fn check_vars(&self, name: &str) {
        assert_eq!(self.vars.len(), VARS.len(), "{name}");
        for (actual, expected) in self.vars.iter().zip(VARS) {
            assert_eq!(actual, expected, "{name}");
        }
    }
}

#[derive(Debug, Deserialize)]
struct ItfState {
    coins: ItfMap,
    edges: ItfMap,
    height: ItfInt,
    #[serde(rename = "liveEdges")]
    live_edges: ItfSet,
}

impl ItfState {
    fn live_coins(&self) -> usize {
        self.coins.non_zero()
    }

    const fn live_edges(&self) -> usize {
        self.live_edges.items.len()
    }
}

#[derive(Debug, Deserialize)]
struct ItfMap {
    #[serde(rename = "#map")]
    items: Vec<(ItfTag, ItfInt)>,
}

impl ItfMap {
    fn get(&self, tag: &str) -> u64 {
        for (item, value) in &self.items {
            if item.tag == tag {
                return value.as_u64();
            }
        }

        panic!("missing ITF map item: {tag}");
    }

    fn non_zero(&self) -> usize {
        self.items
            .iter()
            .filter(|(_, value)| value.as_u64() != 0)
            .count()
    }
}

#[derive(Debug, Deserialize)]
struct ItfSet {
    #[serde(rename = "#set")]
    items: Vec<ItfTag>,
}

impl ItfSet {
    fn contains(&self, tag: &str) -> bool {
        self.items.iter().any(|item| item.tag == tag)
    }
}

#[derive(Debug, Deserialize)]
struct ItfTag {
    tag: String,
}

#[derive(Debug, Deserialize)]
struct ItfInt {
    #[serde(rename = "#bigint")]
    value: String,
}

impl ItfInt {
    fn as_u64(&self) -> u64 {
        let Ok(value) = self.value.parse() else {
            panic!("invalid ITF integer: {}", self.value);
        };
        value
    }
}
