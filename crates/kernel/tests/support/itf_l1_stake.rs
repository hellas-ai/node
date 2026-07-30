#![allow(clippy::enum_variant_names)]

//! ITF schema for `models/l1_stake.qnt`.
//!
//! Field order and names mirror the model's state vars exactly. Every
//! field declared here is read by [`super::super::L1StakeRunner`] —
//! a field that is deserialized but never asserted is not a
//! correspondence, it is decoration.

use itf::de::{As, Integer, Same};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use super::l1_stake as model;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    pub(crate) bond_live: bool,
    pub(crate) bond_terms: VariantTag,
    #[serde(with = "As::<Integer>")]
    pub(crate) bond_value: i64,
    pub(crate) close_outcome: CloseOutcomeTag,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) coins: BTreeMap<CoinTag, i64>,
    #[serde(with = "As::<Integer>")]
    pub(crate) height: i64,
    pub(crate) last_event: Event,
    pub(crate) last_input: Input,
    pub(crate) live_coins: BTreeSet<CoinTag>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CoinTag {
    ProviderCoin,
    ClientAward,
    TreasuryRemainder,
    ProviderReturn,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum VariantTag {
    Valid,
    StakeMismatch,
    ZeroAward,
    AwardAboveStake,
    AwardBelowFloor,
    TreasuryIsParty,
    JobPriceCapZero,
    ChallengeMarginZero,
}

impl VariantTag {
    pub(crate) const fn to_model(self) -> model::Variant {
        match self {
            Self::Valid => model::Variant::Valid,
            Self::StakeMismatch => model::Variant::StakeMismatch,
            Self::ZeroAward => model::Variant::ZeroAward,
            Self::AwardAboveStake => model::Variant::AwardAboveStake,
            Self::AwardBelowFloor => model::Variant::AwardBelowFloor,
            Self::TreasuryIsParty => model::Variant::TreasuryIsParty,
            Self::JobPriceCapZero => model::Variant::JobPriceCapZero,
            Self::ChallengeMarginZero => model::Variant::ChallengeMarginZero,
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
    pub(crate) const fn to_model(self) -> model::ProofKey {
        match self {
            Self::Mutual => model::ProofKey::Mutual,
            Self::Timeout => model::ProofKey::Timeout,
            Self::Violation => model::ProofKey::Violation,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CloseOutcomeTag {
    Unclosed,
    ClosedViolation,
    ClosedTimeout,
}

/// Payouts a close input carries. `second` is unused for `Timeout`,
/// which has a single output.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClosePayouts {
    pub(crate) proof: ProofTag,
    #[serde(with = "As::<Integer>")]
    pub(crate) first: i64,
    #[serde(with = "As::<Integer>")]
    pub(crate) second: i64,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Input {
    NoInput,
    OpenInput(VariantTag),
    RejectedOpenInput(VariantTag),
    CloseInput(ClosePayouts),
    RejectedCloseInput(ClosePayouts),
    TickInput,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Event {
    NoEvent,
    EdgeOpenedEvent,
    EdgeClosedEvent,
}
