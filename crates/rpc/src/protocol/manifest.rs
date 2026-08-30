use core::fmt;

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
