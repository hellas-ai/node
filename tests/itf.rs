#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::expect_used)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]

//! ITF fixture replay against concrete Rust state.
//!
//! Quint emits each abstract trace as an `Informal Trace Format` JSON file
//! under `models/traces/`. Each state in the trace records the action that
//! produced it (`lastInput`) and the abstract event it emitted (`lastEvent`).
//! The runner here implements `itf::Runner`: it deserializes every fixture
//! into the abstract `State` (defined in `support::itf`), reads `lastInput`,
//! drives the kernel with the corresponding `Op`, and asserts that
//!
//!   - the kernel's emitted `Event` matches the abstract `lastEvent`
//!     (`result_invariant`), and
//!   - the kernel's live coin/edge shape matches the abstract `coins`,
//!     `edges`, `liveCoins`, `liveEdges` after every step (`state_invariant`).
//!
//! Adding a new trace test in Quint regenerates a new `.itf.json` fixture
//! that this runner picks up automatically — no Rust changes required.

mod support;

use std::fs;
use std::path::PathBuf;

use itf::Runner as ItfRunner;
use support::{
    FAKE_VERIFIER, coin_view,
    itf::{CoinTag, EdgeTag, Event, Input, State, context_for, edge_key, op_for},
    l1::{
        MAKER, MAKER_ID, TAKER, TAKER_ID, TraceState, TraceView, edge_id, edge_value,
        initial_state, maker_out, taker_out,
    },
};

use hellas_kernel::EventKind;

// -- Runner -----------------------------------------------------------------

struct L1Runner {
    /// Block height under the runner's control. Quint's height advances on
    /// `tick`; the kernel reads height from each `Context`. We track it here
    /// and synthesize the right `Context` for each kernel apply.
    height: i64,
}

impl L1Runner {
    const fn new() -> Self {
        Self { height: 1 }
    }
}

impl ItfRunner for L1Runner {
    type ActualState = TraceState;
    type ExpectedState = State;
    /// `None` means "the input did not produce a kernel event" (e.g.
    /// init/tick/idle steps).
    type Result = Option<EventKind>;
    type Error = String;

    fn init(&mut self, _expected: &Self::ExpectedState) -> Result<Self::ActualState, Self::Error> {
        self.height = 1;
        Ok(initial_state())
    }

    fn step(
        &mut self,
        actual: &mut Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<Self::Result, Self::Error> {
        match &expected.last_input {
            Input::NoInput | Input::IdleInput => Ok(None),
            Input::TickInput => {
                self.height += 1;
                Ok(None)
            }
            Input::OpenInput(_) | Input::CloseInput(_) => {
                let op = op_for(&expected.last_input)
                    .expect("op_for returned None for input that should have produced one");
                let context = context_for(&expected.last_input);
                let event = actual.apply(context, &FAKE_VERIFIER, &op).map_err(|err| {
                    format!("kernel rejected input {:?}: {err:?}", expected.last_input)
                })?;
                Ok(Some(event.kind().clone()))
            }
        }
    }

    fn result_invariant(
        &self,
        result: &Self::Result,
        expected: &Self::ExpectedState,
    ) -> Result<bool, Self::Error> {
        match (result, &expected.last_event) {
            (None, Event::NoEvent) => Ok(true),
            (Some(EventKind::EdgeOpened { output, .. }), Event::EdgeOpenedEvent(expected_edge)) => {
                let want = edge_id(edge_key(*expected_edge));
                if *output == want {
                    Ok(true)
                } else {
                    Err(format!("expected EdgeOpened {want:?}, got {output:?}"))
                }
            }
            (Some(EventKind::EdgeClosed { input, .. }), Event::EdgeClosedEvent(expected_edge)) => {
                let want = edge_id(edge_key(*expected_edge));
                if *input == want {
                    Ok(true)
                } else {
                    Err(format!("expected EdgeClosed {want:?}, got {input:?}"))
                }
            }
            (actual, expected_event) => Err(format!(
                "actual event {actual:?} does not match expected {expected_event:?}",
            )),
        }
    }

    fn state_invariant(
        &self,
        actual: &Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<bool, Self::Error> {
        let view: TraceView = actual.view();

        if expected.height != self.height {
            return Err(format!(
                "model height {} != runner height {}",
                expected.height, self.height,
            ));
        }
        if view.coin_len() != expected.live_coins.len() {
            return Err(format!(
                "live coins: kernel has {}, model has {}",
                view.coin_len(),
                expected.live_coins.len(),
            ));
        }
        if view.edge_len() != expected.live_edges.len() {
            return Err(format!(
                "live edges: kernel has {}, model has {}",
                view.edge_len(),
                expected.live_edges.len(),
            ));
        }

        for (tag, owner, id) in [
            (CoinTag::MakerCoin, MAKER, MAKER_ID),
            (CoinTag::TakerCoin, TAKER, TAKER_ID),
            (
                CoinTag::MakerOut1,
                MAKER,
                maker_out(support::l1::EdgeKey::First),
            ),
            (
                CoinTag::TakerOut1,
                TAKER,
                taker_out(support::l1::EdgeKey::First),
            ),
            (
                CoinTag::MakerOut2,
                MAKER,
                maker_out(support::l1::EdgeKey::Second),
            ),
            (
                CoinTag::TakerOut2,
                TAKER,
                taker_out(support::l1::EdgeKey::Second),
            ),
        ] {
            check_coin(expected, &view, tag, owner, id)?;
        }

        for (tag, edge_key) in [
            (EdgeTag::Edge1, support::l1::EdgeKey::First),
            (EdgeTag::Edge2, support::l1::EdgeKey::Second),
        ] {
            check_edge(expected, &view, tag, edge_id(edge_key))?;
        }

        Ok(true)
    }
}

fn check_coin(
    expected: &State,
    view: &TraceView,
    tag: CoinTag,
    owner: hellas_kernel::Key,
    id: hellas_kernel::CoinId,
) -> Result<bool, String> {
    let coin = view.coin(id).map(coin_view);

    if expected.live_coins.contains(&tag) {
        let value = expected
            .coins
            .get(&tag)
            .copied()
            .map(u64::try_from)
            .and_then(Result::ok)
            .ok_or_else(|| format!("missing or negative coin value: {tag:?}"))?;
        if coin == Some((owner, value)) {
            Ok(true)
        } else {
            Err(format!(
                "{tag:?}: kernel coin {coin:?} != expected ({owner:?}, {value})"
            ))
        }
    } else if coin.is_none() {
        Ok(true)
    } else {
        Err(format!(
            "{tag:?}: kernel has live coin {coin:?}, model does not"
        ))
    }
}

fn check_edge(
    expected: &State,
    view: &TraceView,
    tag: EdgeTag,
    id: hellas_kernel::EdgeId,
) -> Result<bool, String> {
    let live = expected.live_edges.contains(&tag);
    let kernel_edge = view.edge(id).map(edge_value);

    if live {
        let value = expected
            .edges
            .get(&tag)
            .copied()
            .map(u64::try_from)
            .and_then(Result::ok)
            .ok_or_else(|| format!("missing or negative edge value: {tag:?}"))?;
        if kernel_edge == Some(value) {
            Ok(true)
        } else {
            Err(format!(
                "{tag:?}: kernel edge value {kernel_edge:?} != expected {value}"
            ))
        }
    } else if kernel_edge.is_none() {
        Ok(true)
    } else {
        Err(format!(
            "{tag:?}: kernel has live edge {kernel_edge:?}, model does not"
        ))
    }
}

// -- Test entry: discover and replay every committed fixture ----------------

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("models")
        .join("traces")
}

fn load_fixtures() -> Vec<(PathBuf, String)> {
    let dir = fixtures_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .map(|entry| {
            let path = entry.path();
            let json = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
            (path, json)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[test]
fn replays_all_itf_fixtures() {
    let fixtures = load_fixtures();
    assert!(!fixtures.is_empty(), "no ITF fixtures found");

    for (path, json) in fixtures {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let trace: itf::Trace<State> = itf::trace_from_str(&json)
            .unwrap_or_else(|err| panic!("invalid ITF fixture {name}: {err}"));

        let runner = L1Runner::new();
        trace
            .run_on(runner)
            .unwrap_or_else(|err| panic!("fixture {name} replay failed: {err:?}"));
    }
}
