/// Normalized provider-side retention decision.
///
/// Request surfaces may spell this differently (`retain` for Evaluate and
/// OpenAI's `store` for Fetch), but execution code only carries this type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Retention {
    Ephemeral,
    #[default]
    Retain,
}

impl Retention {
    pub const fn from_retain(retain: bool) -> Self {
        if retain {
            Self::Retain
        } else {
            Self::Ephemeral
        }
    }

    pub const fn should_retain(self) -> bool {
        matches!(self, Self::Retain)
    }
}

impl From<bool> for Retention {
    fn from(retain: bool) -> Self {
        Self::from_retain(retain)
    }
}

impl From<Retention> for bool {
    fn from(retention: Retention) -> Self {
        retention.should_retain()
    }
}
