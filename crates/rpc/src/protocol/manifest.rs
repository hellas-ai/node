use crate::{ContentId, DagCborEncoder};

pub const DECODING_PROFILE: &str = "greedy-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluateProgramManifest {
    pub weights: Vec<ContentId>,
    pub graph: ContentId,
    pub config: ContentId,
    pub tokenizer: ContentId,
    pub resolved_revision: String,
    pub numeric_profile: String,
    pub backend_profile: String,
    pub build: ContentId,
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
                e.array(11);
                e.str("hellas.program.manifest.v2");
                e.u64(0);
                e.array(m.weights.len() as u64);
                for id in &m.weights {
                    e.bytes(id.as_bytes());
                }
                e.bytes(m.graph.as_bytes());
                e.bytes(m.config.as_bytes());
                e.bytes(m.tokenizer.as_bytes());
                e.str(&m.resolved_revision);
                e.str(DECODING_PROFILE);
                e.str(&m.numeric_profile);
                e.str(&m.backend_profile);
                e.bytes(m.build.as_bytes());
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
