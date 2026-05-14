use thiserror::Error;

pub const DEFAULT_MODEL_REVISION: &str = "main";

/// Parse errors for [`ModelSpec`]. Carries no external dependencies so it stays
/// WASM-safe for consumers that only need identifier parsing.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ModelSpecError {
    #[error("model id is empty")]
    EmptyId,
    #[error("model revision is empty")]
    EmptyRevision,
}

/// A HuggingFace-style model identifier with an optional revision.
///
/// Parsed from strings of the form `org/model` (revision defaults to
/// [`DEFAULT_MODEL_REVISION`]) or `org/model@revision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelSpec {
    pub id: String,
    pub revision: String,
}

impl ModelSpec {
    pub fn parse(raw: &str) -> Result<Self, ModelSpecError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ModelSpecError::EmptyId);
        }

        let (id, revision) = match raw.rsplit_once('@') {
            Some((id, revision)) => {
                let id = id.trim();
                let revision = revision.trim();
                if id.is_empty() {
                    return Err(ModelSpecError::EmptyId);
                }
                if revision.is_empty() {
                    return Err(ModelSpecError::EmptyRevision);
                }
                (id.to_string(), revision.to_string())
            }
            None => (raw.to_string(), DEFAULT_MODEL_REVISION.to_string()),
        };

        Ok(Self { id, revision })
    }
}

impl std::fmt::Display for ModelSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.revision.is_empty() || self.revision == DEFAULT_MODEL_REVISION {
            write!(f, "{}", self.id)
        } else {
            write!(f, "{}@{}", self.id, self.revision)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MODEL_REVISION, ModelSpec, ModelSpecError};

    #[test]
    fn parses_default_revision_when_not_specified() {
        let spec = ModelSpec::parse("HuggingFaceTB/SmolLM2-135M-Instruct").unwrap();
        assert_eq!(spec.id, "HuggingFaceTB/SmolLM2-135M-Instruct");
        assert_eq!(spec.revision, DEFAULT_MODEL_REVISION);
    }

    #[test]
    fn parses_explicit_revision_suffix() {
        let spec = ModelSpec::parse("foo/bar@refs/pr/7").unwrap();
        assert_eq!(spec.id, "foo/bar");
        assert_eq!(spec.revision, "refs/pr/7");
    }

    #[test]
    fn rejects_empty_revision_suffix() {
        assert_eq!(
            ModelSpec::parse("foo/bar@").unwrap_err(),
            ModelSpecError::EmptyRevision,
        );
    }

    #[test]
    fn rejects_empty_id() {
        assert_eq!(ModelSpec::parse("").unwrap_err(), ModelSpecError::EmptyId,);
        assert_eq!(
            ModelSpec::parse("@main").unwrap_err(),
            ModelSpecError::EmptyId,
        );
    }

    #[test]
    fn display_elides_default_revision() {
        let spec = ModelSpec::parse("org/model").unwrap();
        assert_eq!(spec.to_string(), "org/model");
    }

    #[test]
    fn display_renders_explicit_revision() {
        let spec = ModelSpec::parse("org/model@v2").unwrap();
        assert_eq!(spec.to_string(), "org/model@v2");
    }
}
