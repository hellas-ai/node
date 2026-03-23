use super::{ModelAssetsError, Result};

pub(crate) const DEFAULT_MODEL_REVISION: &str = "main";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelSpec {
    pub(crate) id: String,
    pub(crate) revision: String,
}

impl ModelSpec {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ModelAssetsError::EmptyModelId);
        }

        let (id, revision) = match raw.rsplit_once('@') {
            Some((id, revision)) => {
                let id = id.trim();
                let revision = revision.trim();
                if id.is_empty() {
                    return Err(ModelAssetsError::EmptyModelId);
                }
                if revision.is_empty() {
                    return Err(ModelAssetsError::EmptyModelRevision);
                }
                (id.to_string(), revision.to_string())
            }
            None => (raw.to_string(), DEFAULT_MODEL_REVISION.to_string()),
        };

        Ok(Self { id, revision })
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MODEL_REVISION, ModelSpec};

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
        let err = ModelSpec::parse("foo/bar@").unwrap_err();
        assert!(err.to_string().contains("revision"));
    }
}
