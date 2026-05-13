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
//! under `models/traces/`. Each replay model records the action that produced
//! a state (`lastInput`) and the abstract event it emitted (`lastEvent`). The
//! runners here implement `itf::Runner`: each fixture is deserialized into the
//! schema for its source model, then replayed against concrete Rust state.
//! The checks assert that
//!
//!   - the kernel's emitted `Event` matches the abstract `lastEvent`
//!     (`result_invariant`), and
//!   - the kernel's live coin/edge shape matches the abstract `coins`,
//!     `edges`, `liveCoins`, `liveEdges` after every step (`state_invariant`).
//!
//! Adding a trace test to an existing fixture schema means regenerating
//! fixtures; no Rust changes are needed.

mod support;

use std::fs;
use std::path::PathBuf;

use itf::Runner as ItfRunner;
use support::{
    FAKE_VERIFIER, coin_view,
    itf::PartyTag,
    itf::{CoinTag, EdgeTag, Event, Input, State, context_for_height, edge_key, op_for},
    itf_l1_fees as fee_itf,
    l1::{
        MAKER, MAKER_ID, TAKER, TAKER_ID, TraceState, TraceView, edge_id, edge_value,
        initial_state, maker_out, taker_out,
    },
    l1_fees as fee_model,
};

use hellas_kernel::{EventKind, Fees};

// -- Runner -----------------------------------------------------------------

struct L1Runner;

impl ItfRunner for L1Runner {
    type ActualState = TraceState;
    type ExpectedState = State;
    /// `None` means "the input did not produce a kernel event" (e.g.
    /// init/tick/idle steps).
    type Result = Option<EventKind>;
    type Error = String;

    fn init(&mut self, _expected: &Self::ExpectedState) -> Result<Self::ActualState, Self::Error> {
        Ok(initial_state())
    }

    fn step(
        &mut self,
        actual: &mut Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<Self::Result, Self::Error> {
        match &expected.last_input {
            Input::NoInput | Input::IdleInput | Input::TickInput => Ok(None),
            Input::OpenInput(_) | Input::CloseInput(_) => {
                let op = op_for(&expected.last_input)
                    .expect("op_for returned None for input that should have produced one");
                let context = context_for_height(expected.height)?;
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

        check_open_auth(expected)?;

        Ok(true)
    }
}

struct L1FeesRunner;

impl ItfRunner for L1FeesRunner {
    type ActualState = fee_model::TraceState;
    type ExpectedState = fee_itf::State;
    type Result = Option<EventKind>;
    type Error = String;

    fn init(&mut self, expected: &Self::ExpectedState) -> Result<Self::ActualState, Self::Error> {
        if expected_nonnegative(
            "coins[MakerCoin]",
            expected.coins.get(&fee_itf::CoinTag::MakerCoin).copied(),
        )? == 20
        {
            Ok(fee_model::initial_state_underfunded())
        } else {
            Ok(fee_model::initial_state())
        }
    }

    fn step(
        &mut self,
        actual: &mut Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<Self::Result, Self::Error> {
        match expected.last_input {
            fee_itf::Input::NoInput | fee_itf::Input::IdleInput => Ok(None),
            fee_itf::Input::TickInput | fee_itf::Input::RaiseFeeInput => Ok(None),
            fee_itf::Input::OpenInput(shape_tag) => {
                let shape = shape_tag.to_model();
                let op = fee_model::open(shape);
                let context = fee_model::context(expected.height, fee_model::fees_for_open(shape));
                let event = actual
                    .apply(context, &FAKE_VERIFIER, &op)
                    .map_err(|err| format!("kernel rejected l1_fees open {shape:?}: {err:?}"))?;
                Ok(Some(event.kind().clone()))
            }
            fee_itf::Input::CloseInput(proof_tag) => {
                let proof = proof_tag.to_model();
                let shape = expected_shape(expected)?;
                let op = fee_model::close(shape, proof);
                let context = fee_model::context(
                    expected.height,
                    fees_for_close(expected.current_close_fee)?,
                );
                let event = actual.apply(context, &FAKE_VERIFIER, &op).map_err(|err| {
                    format!(
                        "kernel rejected l1_fees close {:?} for {:?}: {err:?}",
                        proof, shape
                    )
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
            (None, fee_itf::Event::NoEvent) => Ok(true),
            (Some(EventKind::EdgeOpened { output, .. }), fee_itf::Event::EdgeOpenedEvent) => {
                let shape = expected_shape(expected)?;
                let want = fee_model::edge_id(shape);
                if *output == want {
                    Ok(true)
                } else {
                    Err(format!(
                        "expected l1_fees EdgeOpened {want:?}, got {output:?}"
                    ))
                }
            }
            (Some(EventKind::EdgeClosed { input, outputs }), fee_itf::Event::EdgeClosedEvent) => {
                let shape = expected_shape(expected)?;
                let want = fee_model::edge_id(shape);
                let want_outputs = fee_model::output_ids(shape);
                if *input != want {
                    Err(format!(
                        "expected l1_fees EdgeClosed {want:?}, got {input:?}"
                    ))
                } else if *outputs != want_outputs {
                    Err(format!(
                        "expected l1_fees close outputs {want_outputs:?}, got {outputs:?}",
                    ))
                } else {
                    Ok(true)
                }
            }
            (actual, expected_event) => Err(format!(
                "actual l1_fees event {actual:?} does not match expected {expected_event:?}",
            )),
        }
    }

    fn state_invariant(
        &self,
        actual: &Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<bool, Self::Error> {
        let view: fee_model::TraceView = actual.view();

        if view.coin_len() != expected.live_coins.len() {
            return Err(format!(
                "l1_fees live coins: kernel has {}, model has {}",
                view.coin_len(),
                expected.live_coins.len(),
            ));
        }
        if view.edge_len() != expected.live_edges.len() {
            return Err(format!(
                "l1_fees live edges: kernel has {}, model has {}",
                view.edge_len(),
                expected.live_edges.len(),
            ));
        }

        let shape = expected_shape(expected)?;
        for tag in [
            fee_itf::CoinTag::MakerCoin,
            fee_itf::CoinTag::TakerCoin,
            fee_itf::CoinTag::MakerOut,
            fee_itf::CoinTag::TakerOut,
        ] {
            check_fee_coin(expected, &view, tag, shape)?;
        }
        check_fee_edge(expected, &view, shape)?;
        check_fee_open_parties(expected, shape)?;

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

fn check_open_auth(expected: &State) -> Result<bool, String> {
    for tag in &expected.live_edges {
        let auth = expected
            .open_auth
            .get(tag)
            .ok_or_else(|| format!("{tag:?}: missing open auth"))?;
        if (auth.maker, auth.taker) != canonical_auth(*tag) {
            return Err(format!("{tag:?}: unauthorized open auth {auth:?}"));
        }
    }
    Ok(true)
}

const fn canonical_auth(tag: EdgeTag) -> (PartyTag, PartyTag) {
    match tag {
        EdgeTag::Edge1 | EdgeTag::Edge2 => (PartyTag::Maker, PartyTag::Taker),
    }
}

fn expected_shape(expected: &fee_itf::State) -> Result<fee_model::FundingShape, String> {
    expected
        .edge_shape
        .get(&fee_itf::EdgeTag::Channel)
        .copied()
        .map(fee_itf::FundingShapeTag::to_model)
        .ok_or_else(|| "l1_fees missing channel shape".to_owned())
}

fn fees_for_close(current_close_fee: i64) -> Result<Fees, String> {
    match current_close_fee {
        fee_model::BASE_CLOSE_FEE => Ok(fee_model::BASE_FEES),
        fee_model::RAISED_CLOSE_FEE => Ok(fee_model::RAISED_FEES),
        other => Err(format!("unknown l1_fees close fee: {other}")),
    }
}

fn check_fee_coin(
    expected: &fee_itf::State,
    view: &fee_model::TraceView,
    tag: fee_itf::CoinTag,
    shape: fee_model::FundingShape,
) -> Result<bool, String> {
    let (owner, id) = match tag {
        fee_itf::CoinTag::MakerCoin => (fee_model::MAKER, fee_model::MAKER_ID),
        fee_itf::CoinTag::TakerCoin => (fee_model::TAKER, fee_model::TAKER_ID),
        fee_itf::CoinTag::MakerOut => (fee_model::MAKER, fee_model::maker_out(shape)),
        fee_itf::CoinTag::TakerOut => (fee_model::TAKER, fee_model::taker_out(shape)),
    };
    let coin = view.coin(id).map(coin_view);

    if expected.live_coins.contains(&tag) {
        let value = expected
            .coins
            .get(&tag)
            .copied()
            .map(u64::try_from)
            .and_then(Result::ok)
            .ok_or_else(|| format!("missing or negative l1_fees coin value: {tag:?}"))?;
        if coin == Some((owner, value)) {
            Ok(true)
        } else {
            Err(format!(
                "l1_fees {tag:?}: kernel coin {coin:?} != expected ({owner:?}, {value})",
            ))
        }
    } else if coin.is_none() {
        Ok(true)
    } else {
        Err(format!(
            "l1_fees {tag:?}: kernel has live coin {coin:?}, model does not",
        ))
    }
}

fn check_fee_edge(
    expected: &fee_itf::State,
    view: &fee_model::TraceView,
    shape: fee_model::FundingShape,
) -> Result<bool, String> {
    let id = fee_model::edge_id(shape);
    let live = expected.live_edges.contains(&fee_itf::EdgeTag::Channel);
    let edge = view.edge(id);

    if !live {
        return if edge.is_none() {
            Ok(true)
        } else {
            Err("l1_fees kernel has live channel edge, model does not".to_owned())
        };
    }

    let Some(edge) = edge else {
        return Err("l1_fees model has live channel edge, kernel does not".to_owned());
    };
    let expected_value = expected_nonnegative(
        "edges[Channel]",
        expected.edges.get(&fee_itf::EdgeTag::Channel).copied(),
    )?;
    let expected_reserve = expected_nonnegative(
        "reserves[Channel]",
        expected.reserves.get(&fee_itf::EdgeTag::Channel).copied(),
    )?;
    let expected_close_fee = expected_nonnegative(
        "closeFees[Channel]",
        expected.close_fees.get(&fee_itf::EdgeTag::Channel).copied(),
    )?;
    let actual_close_fee = edge
        .close_fees()
        .charge(fee_model::close(shape, fee_model::ProofKey::Mutual).cost())
        .ok_or_else(|| "l1_fees edge close fee overflowed".to_owned())?;

    if edge.value() != expected_value {
        return Err(format!(
            "l1_fees edge value {} != expected {expected_value}",
            edge.value(),
        ));
    }
    if edge.reserve() != expected_reserve {
        return Err(format!(
            "l1_fees edge reserve {} != expected {expected_reserve}",
            edge.reserve(),
        ));
    }
    if actual_close_fee != expected_close_fee {
        return Err(format!(
            "l1_fees edge committed close fee {actual_close_fee} != expected {expected_close_fee}",
        ));
    }
    if edge.timeout() != fee_model::TIMEOUT {
        return Err(format!(
            "l1_fees edge timeout {:?} != expected {:?}",
            edge.timeout(),
            fee_model::TIMEOUT,
        ));
    }
    if edge.parties() != fee_model::parties(shape) {
        return Err(format!(
            "l1_fees edge parties {:?} != expected {:?}",
            edge.parties(),
            fee_model::parties(shape),
        ));
    }
    if edge.terms() != fee_model::terms(shape).hash() {
        return Err("l1_fees edge terms hash does not match expected terms".to_owned());
    }

    Ok(true)
}

fn check_fee_open_parties(
    expected: &fee_itf::State,
    shape: fee_model::FundingShape,
) -> Result<bool, String> {
    if !expected.live_edges.contains(&fee_itf::EdgeTag::Channel) {
        return Ok(true);
    }

    let Some(parties) = expected.edge_parties.get(&fee_itf::EdgeTag::Channel) else {
        return Err("l1_fees live channel missing open parties".to_owned());
    };
    let want = match shape {
        fee_model::FundingShape::SelfEdge => (PartyTag::Maker, PartyTag::Maker),
        fee_model::FundingShape::Full
        | fee_model::FundingShape::MakerOnly
        | fee_model::FundingShape::TakerOnly
        | fee_model::FundingShape::Empty => (PartyTag::Maker, PartyTag::Taker),
    };

    if (parties.maker, parties.taker) == want {
        Ok(true)
    } else {
        Err(format!(
            "l1_fees open parties ({:?}, {:?}) != expected {want:?}",
            parties.maker, parties.taker,
        ))
    }
}

fn expected_nonnegative(name: &str, value: Option<i64>) -> Result<u64, String> {
    value
        .map(u64::try_from)
        .and_then(Result::ok)
        .ok_or_else(|| format!("missing or negative l1_fees {name}"))
}

// -- Test entry: discover and replay every committed fixture ----------------

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FixtureKind {
    L1,
    L1Fees,
}

impl FixtureKind {
    fn from_name(name: &str) -> Option<Self> {
        if name.starts_with("l1_fees_") {
            Some(Self::L1Fees)
        } else if name.starts_with("l1_") {
            Some(Self::L1)
        } else {
            None
        }
    }
}

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
        match FixtureKind::from_name(&name)
            .unwrap_or_else(|| panic!("unrecognized ITF fixture prefix: {name}"))
        {
            FixtureKind::L1 => {
                let trace: itf::Trace<State> = itf::trace_from_str(&json)
                    .unwrap_or_else(|err| panic!("invalid ITF fixture {name}: {err}"));
                trace
                    .run_on(L1Runner)
                    .unwrap_or_else(|err| panic!("fixture {name} replay failed: {err:?}"));
            }
            FixtureKind::L1Fees => {
                let trace: itf::Trace<fee_itf::State> = itf::trace_from_str(&json)
                    .unwrap_or_else(|err| panic!("invalid ITF fixture {name}: {err}"));
                trace
                    .run_on(L1FeesRunner)
                    .unwrap_or_else(|err| panic!("fixture {name} replay failed: {err:?}"));
            }
        }
    }
}
