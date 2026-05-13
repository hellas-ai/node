#![allow(clippy::enum_variant_names)]
#![allow(clippy::expect_used)]

//! Shared ITF (Informal Trace Format) schema and op conversion.
//!
//! Quint emits each abstract trace under `models/traces/` as an ITF JSON
//! file. The schema mirrors the state vars in `models/l1.qnt` exactly —
//! the `itf` crate validates the trace's variable list against this
//! struct's fields at parse time.
//!
//! The conversion functions turn abstract ITF state into the concrete
//! `(Context, Op)` the kernel consumes. Both `tests/itf.rs` (validation
//! replay) and `benches/apply.rs` (throughput) drive the kernel through the
//! same conversion, so a fixture replayed in either place exercises the same
//! kernel paths.

use std::collections::{BTreeMap, BTreeSet};

use itf::de::{As, Integer, Same};
use serde::Deserialize;

use hellas_kernel::{
    BlockHash, BlockHeight, CloseKind, Context, EdgeId, List, MAX_EDGE_OUTPUTS, Payout, Proof,
    ProtocolCode, Seal, Sig, Tx,
};

use super::l1;

// -- Abstract types mirrored from models/l1.qnt -----------------------------

/// Abstract state mirrored from `models/l1.qnt`. Field order and names
/// must match the Quint declarations exactly; the `itf` crate verifies
/// the trace's variable list against the struct's fields at parse time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) coins: BTreeMap<CoinTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) edges: BTreeMap<EdgeTag, i64>,
    #[serde(with = "As::<Integer>")]
    pub(crate) height: i64,
    pub(crate) last_event: Event,
    pub(crate) last_input: Input,
    pub(crate) live_coins: BTreeSet<CoinTag>,
    pub(crate) live_edges: BTreeSet<EdgeTag>,
    pub(crate) open_auth: BTreeMap<EdgeTag, OpenAuthBody>,
}

/// Quint `Coin` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CoinTag {
    MakerCoin,
    TakerCoin,
    MakerOut1,
    TakerOut1,
    MakerOut2,
    TakerOut2,
}

/// Quint `Edge` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum EdgeTag {
    Edge1,
    Edge2,
}

/// Quint `Proof` enum, mirrored from the collapsed kernel proof surface.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum ProofTag {
    Mutual,
    Timeout,
    Violation,
}

/// Quint `Party` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum PartyTag {
    Maker,
    Taker,
    Adversary,
}

/// Quint `OpenAuth` record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub(crate) struct OpenAuthBody {
    pub(crate) maker: PartyTag,
    pub(crate) taker: PartyTag,
}

/// Quint `Input` ADT.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Input {
    NoInput,
    OpenInput(EdgeTag),
    CloseInput(CloseInputBody),
    TickInput,
    IdleInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CloseInputBody {
    pub(crate) edge: EdgeTag,
    pub(crate) proof: ProofTag,
    #[serde(with = "As::<Integer>")]
    pub(crate) maker_pay: i64,
    #[serde(with = "As::<Integer>")]
    pub(crate) taker_pay: i64,
}

/// Quint `Event` ADT (abstract event emitted by the action that produced
/// the state).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Event {
    NoEvent,
    EdgeOpenedEvent(EdgeTag),
    EdgeClosedEvent(EdgeTag),
}

// -- Conversion -------------------------------------------------------------

/// Maps `EdgeTag` to the corresponding model edge key.
pub(crate) const fn edge_key(tag: EdgeTag) -> l1::EdgeKey {
    match tag {
        EdgeTag::Edge1 => l1::EdgeKey::First,
        EdgeTag::Edge2 => l1::EdgeKey::Second,
    }
}

/// Synthesizes the kernel `Context` from the height carried by an ITF state.
pub(crate) fn context_for_height(height: i64) -> Result<Context, String> {
    let height = u64::try_from(height).map_err(|_| format!("negative l1 height: {height}"))?;
    Ok(Context::new(
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    ))
}

/// Concrete `Tx` (when the input maps to one). `NoInput`, `TickInput`,
/// and `IdleInput` produce no kernel work.
pub(crate) fn op_for(input: &Input) -> Option<Tx> {
    match input {
        Input::OpenInput(tag) => Some(l1::open(edge_key(*tag))),
        Input::CloseInput(body) => Some(close_op(body)),
        Input::NoInput | Input::TickInput | Input::IdleInput => None,
    }
}

/// Builds a close `Tx` from a model `CloseInput`. Payouts are taken
/// from the model body, not the support helper, so adversarial-payout
/// traces drive the kernel correctly.
pub(crate) fn close_op(body: &CloseInputBody) -> Tx {
    let edge = edge_key(body.edge);
    let outputs = l1::payouts_with(
        u64::try_from(body.maker_pay).expect("negative maker payout"),
        u64::try_from(body.taker_pay).expect("negative taker payout"),
    );
    let input = l1::edge_id(edge);
    let terms = l1::terms();
    let proof = match body.proof {
        ProofTag::Mutual => {
            let hash = Tx::payload_hash(input, CloseKind::Mutual, terms.hash(), &outputs);
            Proof::mutual(
                Sig::placeholder(l1::MAKER, hash),
                Sig::placeholder(l1::TAKER, hash),
            )
        }
        ProofTag::Timeout => Proof::timeout(terms),
        ProofTag::Violation => Proof::violation(terms, seal_for(input, &outputs)),
    };
    Tx::close(input, proof, outputs)
}

fn seal_for(input: EdgeId, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    let hash = Tx::payload_hash(input, CloseKind::Violation, l1::terms().hash(), outputs);
    Seal::placeholder(ProtocolCode::new(1), CloseKind::Violation, hash)
}
