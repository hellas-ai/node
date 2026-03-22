use std::fmt;
use std::str::FromStr;

use super::glob;
use super::parse_allow_patterns;

/// Controls whether the executor may download model weights from `HuggingFace`.
#[derive(Clone, Debug, Default)]
pub enum DownloadPolicy {
    /// Download any model if not cached (default).
    #[default]
    Eager,
    /// Download only models whose `HuggingFace` model ID matches one of the
    /// given glob patterns; deny all others unless already cached locally.
    Allow(Vec<String>),
    /// Never download; only use models already present in the local HF cache.
    Skip,
}

impl DownloadPolicy {
    /// Returns `true` if this policy permits downloading the given model.
    pub(crate) fn allows_download(&self, model_id: &str) -> bool {
        match self {
            Self::Eager => true,
            Self::Skip => false,
            Self::Allow(patterns) => patterns
                .iter()
                .any(|pattern| glob::matches(pattern, model_id)),
        }
    }
}

impl FromStr for DownloadPolicy {
    type Err = String;

    fn from_str(policy: &str) -> Result<Self, Self::Err> {
        let trimmed = policy.trim();
        match trimmed {
            "eager" => Ok(Self::Eager),
            "skip" => Ok(Self::Skip),
            _ if trimmed.starts_with("allow(") => Ok(Self::Allow(parse_allow_patterns(trimmed)?)),
            _ => Err(format!(
                "invalid download policy '{trimmed}': expected 'eager', 'skip', or 'allow(pattern,...)'"
            )),
        }
    }
}

impl fmt::Display for DownloadPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eager => write!(f, "eager"),
            Self::Skip => write!(f, "skip"),
            Self::Allow(patterns) => write!(f, "allow({})", patterns.join(",")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DownloadPolicy;

    #[test]
    fn parse_eager() {
        let policy: DownloadPolicy = "eager".parse().unwrap();
        assert!(matches!(policy, DownloadPolicy::Eager));
        assert_eq!(policy.to_string(), "eager");
    }

    #[test]
    fn parse_skip() {
        let policy: DownloadPolicy = "skip".parse().unwrap();
        assert!(matches!(policy, DownloadPolicy::Skip));
        assert_eq!(policy.to_string(), "skip");
    }

    #[test]
    fn parse_allow_single() {
        let policy: DownloadPolicy = "allow(Qwen3/*)".parse().unwrap();
        match &policy {
            DownloadPolicy::Allow(patterns) => assert_eq!(patterns, &["Qwen3/*"]),
            _ => panic!("expected Allow"),
        }
        assert_eq!(policy.to_string(), "allow(Qwen3/*)");
    }

    #[test]
    fn parse_allow_multiple() {
        let policy: DownloadPolicy = "allow(Qwen3/*, meta-llama/*)".parse().unwrap();
        match &policy {
            DownloadPolicy::Allow(patterns) => {
                assert_eq!(patterns, &["Qwen3/*", "meta-llama/*"]);
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_invalid() {
        assert!("unknown".parse::<DownloadPolicy>().is_err());
        assert!("allow()".parse::<DownloadPolicy>().is_err());
    }

    #[test]
    fn allows_download() {
        assert!(DownloadPolicy::Eager.allows_download("anything"));
        assert!(!DownloadPolicy::Skip.allows_download("anything"));

        let policy = DownloadPolicy::Allow(vec!["Qwen3/*".into(), "meta-llama/*".into()]);
        assert!(policy.allows_download("Qwen3/Qwen3-0.6B"));
        assert!(policy.allows_download("meta-llama/Llama-3.1-8B"));
        assert!(!policy.allows_download("HuggingFaceTB/SmolLM2-135M"));
    }
}
