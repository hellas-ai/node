#![allow(clippy::enum_variant_names)]

//! ITF schema for `models/l1_fees.qnt`.

use std::collections::{BTreeMap, BTreeSet};

use itf::de::{As, Integer, Same};
use serde::Deserialize;

use super::itf::PartyTag;
use super::l1_fees;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) coins: BTreeMap<CoinTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) edges: BTreeMap<EdgeTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) reserves: BTreeMap<EdgeTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) close_fees: BTreeMap<EdgeTag, i64>,
    pub(crate) edge_shape: BTreeMap<EdgeTag, FundingShapeTag>,
    pub(crate) edge_parties: BTreeMap<EdgeTag, OpenParties>,
    pub(crate) live_coins: BTreeSet<CoinTag>,
    pub(crate) live_edges: BTreeSet<EdgeTag>,
    #[serde(with = "As::<Integer>")]
    pub(crate) paid: i64,
    #[serde(with = "As::<Integer>")]
    pub(crate) height: i64,
    #[serde(with = "As::<Integer>")]
    pub(crate) current_close_fee: i64,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) posted_stake: BTreeMap<PartyTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) stake_awards: BTreeMap<PartyTag, i64>,
    pub(crate) close_outcome: CloseOutcomeTag,
    pub(crate) last_input: Input,
    pub(crate) last_event: Event,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CoinTag {
    MakerCoin,
    TakerCoin,
    MakerOut,
    TakerOut,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum EdgeTag {
    Channel,
    UnusedEdge,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum FundingShapeTag {
    FullFunding,
    MakerOnlyFunding,
    TakerOnlyFunding,
    EmptyFunding,
    SelfFunding,
}

impl FundingShapeTag {
    pub(crate) const fn to_model(self) -> l1_fees::FundingShape {
        match self {
            Self::FullFunding => l1_fees::FundingShape::Full,
            Self::MakerOnlyFunding => l1_fees::FundingShape::MakerOnly,
            Self::TakerOnlyFunding => l1_fees::FundingShape::TakerOnly,
            Self::EmptyFunding => l1_fees::FundingShape::Empty,
            Self::SelfFunding => l1_fees::FundingShape::SelfEdge,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum ProofTag {
    Mutual,
    Timeout,
    Violation,
}

impl ProofTag {
    pub(crate) const fn to_model(self) -> l1_fees::ProofKey {
        match self {
            Self::Mutual => l1_fees::ProofKey::Mutual,
            Self::Timeout => l1_fees::ProofKey::Timeout,
            Self::Violation => l1_fees::ProofKey::Violation,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CloseOutcomeTag {
    NoClose,
    ClosedMutual,
    ClosedTimeout,
    ClosedViolation,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub(crate) struct OpenParties {
    pub(crate) maker: PartyTag,
    pub(crate) taker: PartyTag,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Input {
    NoInput,
    OpenInput(FundingShapeTag),
    CloseInput(ProofTag),
    RejectedOpenInput(FundingShapeTag),
    RejectedCloseInput(ProofTag),
    RaiseFeeInput,
    TickInput,
    IdleInput,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Event {
    NoEvent,
    EdgeOpenedEvent,
    EdgeClosedEvent,
}
