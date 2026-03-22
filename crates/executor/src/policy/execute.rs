use std::fmt;
use std::str::FromStr;

use super::glob;
use super::parse_allow_patterns;

/// A namespaced pattern for execute policy matching.
#[derive(Clone, Debug)]
pub enum ExecutePattern {
    /// `hf/<glob>` matches on the `HuggingFace` model ID.
    HuggingFace(String),
    /// `graph/<glob>` matches on the blake3 graph hash.
    Graph(String),
}

/// Controls which graphs the executor will run.
#[derive(Clone, Debug, Default)]
pub enum ExecutePolicy {
    /// Execute any graph (default).
    #[default]
    Eager,
    /// Execute only graphs matching one of the given patterns.
    Allow(Vec<ExecutePattern>),
    /// Refuse all executions.
    Skip,
}

impl ExecutePolicy {
    /// Returns `true` if this policy permits executing a graph with the given
    /// identifiers. For LLM graphs `hf_model_id` is `Some(id)`; for raw graphs
    /// it is `None`.
    pub(crate) fn allows_execute(&self, graph_id: &str, hf_model_id: Option<&str>) -> bool {
        match self {
            Self::Eager => true,
            Self::Skip => false,
            Self::Allow(patterns) => patterns.iter().any(|pattern| match pattern {
                ExecutePattern::HuggingFace(pattern) => {
                    hf_model_id.is_some_and(|model_id| glob::matches(pattern, model_id))
                }
                ExecutePattern::Graph(pattern) => glob::matches(pattern, graph_id),
            }),
        }
    }
}

impl FromStr for ExecutePolicy {
    type Err = String;

    fn from_str(policy: &str) -> Result<Self, Self::Err> {
        let trimmed = policy.trim();
        match trimmed {
            "eager" => Ok(Self::Eager),
            "skip" => Ok(Self::Skip),
            _ if trimmed.starts_with("allow(") => {
                let patterns = parse_allow_patterns(trimmed)?
                    .iter()
                    .map(|pattern| ExecutePattern::parse(pattern))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Allow(patterns))
            }
            _ => Err(format!(
                "invalid execute policy '{trimmed}': expected 'eager', 'skip', or 'allow(hf/pattern,...,graph/pattern,...)'"
            )),
        }
    }
}

impl fmt::Display for ExecutePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eager => write!(f, "eager"),
            Self::Skip => write!(f, "skip"),
            Self::Allow(patterns) => {
                write!(f, "allow(")?;
                for (index, pattern) in patterns.iter().enumerate() {
                    if index > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{pattern}")?;
                }
                write!(f, ")")
            }
        }
    }
}

impl ExecutePattern {
    fn parse(pattern: &str) -> Result<Self, String> {
        if let Some(rest) = pattern.strip_prefix("hf/") {
            if rest.is_empty() {
                return Err("hf/ pattern must not be empty".to_string());
            }
            Ok(Self::HuggingFace(rest.to_string()))
        } else if let Some(rest) = pattern.strip_prefix("graph/") {
            if rest.is_empty() {
                return Err("graph/ pattern must not be empty".to_string());
            }
            Ok(Self::Graph(rest.to_string()))
        } else {
            Err(format!(
                "execute pattern '{pattern}' must start with 'hf/' or 'graph/'"
            ))
        }
    }
}

impl fmt::Display for ExecutePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HuggingFace(pattern) => write!(f, "hf/{pattern}"),
            Self::Graph(pattern) => write!(f, "graph/{pattern}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutePattern, ExecutePolicy};

    #[test]
    fn parse_eager() {
        let policy: ExecutePolicy = "eager".parse().unwrap();
        assert!(matches!(policy, ExecutePolicy::Eager));
        assert_eq!(policy.to_string(), "eager");
    }

    #[test]
    fn parse_skip() {
        let policy: ExecutePolicy = "skip".parse().unwrap();
        assert!(matches!(policy, ExecutePolicy::Skip));
    }

    #[test]
    fn parse_allow_hf() {
        let policy: ExecutePolicy = "allow(hf/Qwen3/*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(
                    matches!(&patterns[0], ExecutePattern::HuggingFace(pattern) if pattern == "Qwen3/*")
                );
            }
            _ => panic!("expected Allow"),
        }
        assert_eq!(policy.to_string(), "allow(hf/Qwen3/*)");
    }

    #[test]
    fn parse_allow_graph() {
        let policy: ExecutePolicy = "allow(graph/abc123*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(
                    matches!(&patterns[0], ExecutePattern::Graph(pattern) if pattern == "abc123*")
                );
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_allow_mixed() {
        let policy: ExecutePolicy = "allow(hf/Qwen3/*,graph/abc*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(
                    matches!(&patterns[0], ExecutePattern::HuggingFace(pattern) if pattern == "Qwen3/*")
                );
                assert!(
                    matches!(&patterns[1], ExecutePattern::Graph(pattern) if pattern == "abc*")
                );
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_invalid_namespace() {
        assert!("allow(unknown/foo)".parse::<ExecutePolicy>().is_err());
    }

    #[test]
    fn allows_execute() {
        assert!(ExecutePolicy::Eager.allows_execute("anyhash", Some("any/model")));
        assert!(ExecutePolicy::Eager.allows_execute("anyhash", None));
        assert!(!ExecutePolicy::Skip.allows_execute("anyhash", Some("any/model")));

        let hf_only = ExecutePolicy::Allow(vec![ExecutePattern::HuggingFace("Qwen3/*".into())]);
        assert!(hf_only.allows_execute("", Some("Qwen3/Qwen3-0.6B")));
        assert!(!hf_only.allows_execute("", Some("meta-llama/X")));
        assert!(!hf_only.allows_execute("somehash", None));

        let graph_only = ExecutePolicy::Allow(vec![ExecutePattern::Graph("abc*".into())]);
        assert!(graph_only.allows_execute("abc123", None));
        assert!(!graph_only.allows_execute("def456", None));
        assert!(graph_only.allows_execute("abc123", Some("anything")));

        let mixed = ExecutePolicy::Allow(vec![
            ExecutePattern::HuggingFace("Qwen3/*".into()),
            ExecutePattern::Graph("abc*".into()),
        ]);
        assert!(mixed.allows_execute("xyz", Some("Qwen3/Qwen3-0.6B")));
        assert!(mixed.allows_execute("abc123", Some("unknown/model")));
        assert!(!mixed.allows_execute("def456", Some("unknown/model")));
    }
}
