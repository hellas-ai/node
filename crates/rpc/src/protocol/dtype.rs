use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dtype {
    F32,
    F16,
    BF16,
    F8,
    U32,
}

impl Dtype {
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F16 => "f16",
            Self::BF16 => "bf16",
            Self::F8 => "f8",
            Self::U32 => "u32",
        }
    }

    pub const fn is_model_dtype(self) -> bool {
        !matches!(self, Self::U32)
    }
}

impl fmt::Display for Dtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown dtype `{0}`; expected one of f32, f16, bf16, f8, u32")]
pub struct ParseDtypeError(String);

impl FromStr for Dtype {
    type Err = ParseDtypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "f32" => Ok(Self::F32),
            "f16" => Ok(Self::F16),
            "bf16" => Ok(Self::BF16),
            "f8" => Ok(Self::F8),
            "u32" => Ok(Self::U32),
            other => Err(ParseDtypeError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trips_every_variant() {
        for dtype in [Dtype::F32, Dtype::F16, Dtype::BF16, Dtype::F8, Dtype::U32] {
            assert_eq!(Dtype::from_str(dtype.as_wire()).unwrap(), dtype);
        }
    }

    #[test]
    fn unknown_wire_is_rejected() {
        assert!(Dtype::from_str("bf8").is_err());
    }

    #[test]
    fn u32_is_not_a_model_dtype() {
        assert!(!Dtype::U32.is_model_dtype());
        assert!(Dtype::F32.is_model_dtype());
    }
}
