use core::{fmt, str::FromStr};

use crate::{ContentId, DagCborEncoder};

/// The exact executable Catena package a text evaluation runs.
///
/// This is an opaque digest produced by the Catena package verifier. Hellas
/// deliberately does not reinterpret it as one of its own content IDs: the
/// producer and hash domain belong to Catena, while the surrounding
/// [`ProgramManifest`] is content-addressed by Hellas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionPackageId([u8; 32]);

impl ExecutionPackageId {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for ExecutionPackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ExecutionPackageId {
    type Err = ExecutionPackageIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != Self::LEN * 2 {
            return Err(ExecutionPackageIdParseError::Length(value.len()));
        }
        let mut bytes = [0_u8; Self::LEN];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0])
                .ok_or(ExecutionPackageIdParseError::Hex(index.saturating_mul(2)))?;
            let low = hex_nibble(pair[1]).ok_or(ExecutionPackageIdParseError::Hex(
                index.saturating_mul(2).saturating_add(1),
            ))?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self::from_bytes(bytes))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionPackageIdParseError {
    Length(usize),
    Hex(usize),
}

impl fmt::Display for ExecutionPackageIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(length) => write!(
                formatter,
                "Catena execution package ID must be exactly 64 hexadecimal characters (got {length})"
            ),
            Self::Hex(index) => write!(
                formatter,
                "Catena execution package ID contains a non-hexadecimal character at byte {index}"
            ),
        }
    }
}

impl core::error::Error for ExecutionPackageIdParseError {}

/// The token-level execution contract implemented by this manifest schema.
///
/// Tokenization, chat templating, and text decoding are outside this profile:
/// the committed inputs and outputs are token IDs.
pub const CATENA_TOKEN_AUTOREGRESSIVE_PROFILE: &str =
    "hellas.evaluate.catena.token-autoregressive.greedy.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluateProgramManifest {
    pub execution_package: ExecutionPackageId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchProgramManifest {
    pub program: ContentId,
    pub config: ContentId,
    pub build: ContentId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramManifest {
    Evaluate(EvaluateProgramManifest),
    Fetch(FetchProgramManifest),
}

impl ProgramManifest {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        match self {
            Self::Evaluate(m) => {
                e.array(4);
                e.str("hellas.program.manifest.v3");
                e.u64(0);
                e.str(CATENA_TOKEN_AUTOREGRESSIVE_PROFILE);
                e.bytes(m.execution_package.as_bytes());
            }
            Self::Fetch(m) => {
                e.array(5);
                e.str("hellas.program.manifest.v2");
                e.u64(1);
                e.bytes(m.program.as_bytes());
                e.bytes(m.config.as_bytes());
                e.bytes(m.build.as_bytes());
            }
        }
        e.into_bytes()
    }

    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }
}
