use std::fmt;
use std::str::FromStr;

/// Simple glob match supporting `*` as a wildcard for any sequence of characters.
pub(crate) fn glob_matches(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(found) => {
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    if let Some(last) = parts.last() {
        if !last.is_empty() {
            return pos == text.len();
        }
    }

    true
}

fn parse_allow_patterns(s: &str) -> Result<Vec<String>, String> {
    let trimmed = s.trim();
    if !trimmed.starts_with("allow(") || !trimmed.ends_with(')') {
        return Err(format!("expected 'allow(pattern,...)' but got '{trimmed}'"));
    }
    let inner = &trimmed["allow(".len()..trimmed.len() - 1];
    let patterns: Vec<String> = inner
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if patterns.is_empty() {
        return Err("allow() requires at least one pattern".to_string());
    }
    Ok(patterns)
}

// ---------------------------------------------------------------------------
// DownloadPolicy
// ---------------------------------------------------------------------------

/// Controls whether the executor may download model weights from HuggingFace.
#[derive(Clone, Debug)]
pub enum DownloadPolicy {
    /// Download any model if not cached (default).
    Eager,
    /// Download only models whose HuggingFace model ID matches one of the
    /// given glob patterns; deny all others unless already cached locally.
    Allow(Vec<String>),
    /// Never download; only use models already present in the local HF cache.
    Skip,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        Self::Eager
    }
}

impl DownloadPolicy {
    /// Returns `true` if this policy permits downloading the given model.
    pub(crate) fn allows_download(&self, model_id: &str) -> bool {
        match self {
            Self::Eager => true,
            Self::Skip => false,
            Self::Allow(patterns) => patterns.iter().any(|pat| glob_matches(pat, model_id)),
        }
    }
}

impl FromStr for DownloadPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        match trimmed {
            "eager" => Ok(Self::Eager),
            "skip" => Ok(Self::Skip),
            _ if trimmed.starts_with("allow(") => {
                let patterns = parse_allow_patterns(trimmed)?;
                Ok(Self::Allow(patterns))
            }
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

// ---------------------------------------------------------------------------
// ExecutePolicy
// ---------------------------------------------------------------------------

/// A namespaced pattern for execute policy matching.
#[derive(Clone, Debug)]
pub enum ExecutePattern {
    /// `hf/<glob>` — matches on the HuggingFace model ID.
    HuggingFace(String),
    /// `graph/<glob>` — matches on the blake3 graph hash.
    Graph(String),
}

/// Controls which graphs the executor will run.
#[derive(Clone, Debug)]
pub enum ExecutePolicy {
    /// Execute any graph (default).
    Eager,
    /// Execute only graphs matching one of the given patterns.
    Allow(Vec<ExecutePattern>),
    /// Refuse all executions.
    Skip,
}

impl Default for ExecutePolicy {
    fn default() -> Self {
        Self::Eager
    }
}

impl ExecutePolicy {
    /// Returns `true` if this policy permits executing a graph with the given
    /// identifiers.  For LLM graphs `hf_model_id` is `Some(id)`; for raw
    /// graphs it is `None`.
    pub(crate) fn allows_execute(&self, graph_id: &str, hf_model_id: Option<&str>) -> bool {
        match self {
            Self::Eager => true,
            Self::Skip => false,
            Self::Allow(patterns) => patterns.iter().any(|p| match p {
                ExecutePattern::HuggingFace(pat) => {
                    hf_model_id.map_or(false, |id| glob_matches(pat, id))
                }
                ExecutePattern::Graph(pat) => glob_matches(pat, graph_id),
            }),
        }
    }
}

fn parse_execute_pattern(s: &str) -> Result<ExecutePattern, String> {
    if let Some(rest) = s.strip_prefix("hf/") {
        if rest.is_empty() {
            return Err("hf/ pattern must not be empty".to_string());
        }
        Ok(ExecutePattern::HuggingFace(rest.to_string()))
    } else if let Some(rest) = s.strip_prefix("graph/") {
        if rest.is_empty() {
            return Err("graph/ pattern must not be empty".to_string());
        }
        Ok(ExecutePattern::Graph(rest.to_string()))
    } else {
        Err(format!(
            "execute pattern '{s}' must start with 'hf/' or 'graph/'"
        ))
    }
}

impl FromStr for ExecutePolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        match trimmed {
            "eager" => Ok(Self::Eager),
            "skip" => Ok(Self::Skip),
            _ if trimmed.starts_with("allow(") => {
                let raw = parse_allow_patterns(trimmed)?;
                let patterns = raw
                    .iter()
                    .map(|p| parse_execute_pattern(p))
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
                for (i, p) in patterns.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    match p {
                        ExecutePattern::HuggingFace(pat) => write!(f, "hf/{pat}")?,
                        ExecutePattern::Graph(pat) => write!(f, "graph/{pat}")?,
                    }
                }
                write!(f, ")")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- glob_matches -------------------------------------------------------

    #[test]
    fn glob_exact_match() {
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "exactX"));
        assert!(!glob_matches("exact", "Xexact"));
    }

    #[test]
    fn glob_trailing_star() {
        assert!(glob_matches("Qwen3/*", "Qwen3/Qwen3-0.6B"));
        assert!(glob_matches("Qwen3/*", "Qwen3/anything"));
        assert!(!glob_matches("Qwen3/*", "meta-llama/Llama-3"));
    }

    #[test]
    fn glob_leading_star() {
        assert!(glob_matches("*-Instruct", "SmolLM2-135M-Instruct"));
        assert!(!glob_matches("*-Instruct", "SmolLM2-135M"));
    }

    #[test]
    fn glob_middle_star() {
        assert!(glob_matches("meta-llama/Llama*8B", "meta-llama/Llama-3.1-8B"));
        assert!(!glob_matches("meta-llama/Llama*8B", "meta-llama/Llama-3.1-70B"));
    }

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_matches("*", "anything/at-all"));
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(glob_matches("*llama*8B", "meta-llama/Llama-3.1-8B"));
        assert!(!glob_matches("*llama*70B", "meta-llama/Llama-3.1-8B"));
    }

    // -- DownloadPolicy parsing ---------------------------------------------

    #[test]
    fn parse_download_eager() {
        let p: DownloadPolicy = "eager".parse().unwrap();
        assert!(matches!(p, DownloadPolicy::Eager));
        assert_eq!(p.to_string(), "eager");
    }

    #[test]
    fn parse_download_skip() {
        let p: DownloadPolicy = "skip".parse().unwrap();
        assert!(matches!(p, DownloadPolicy::Skip));
        assert_eq!(p.to_string(), "skip");
    }

    #[test]
    fn parse_download_allow_single() {
        let p: DownloadPolicy = "allow(Qwen3/*)".parse().unwrap();
        match &p {
            DownloadPolicy::Allow(pats) => assert_eq!(pats, &["Qwen3/*"]),
            _ => panic!("expected Allow"),
        }
        assert_eq!(p.to_string(), "allow(Qwen3/*)");
    }

    #[test]
    fn parse_download_allow_multiple() {
        let p: DownloadPolicy = "allow(Qwen3/*, meta-llama/*)".parse().unwrap();
        match &p {
            DownloadPolicy::Allow(pats) => {
                assert_eq!(pats, &["Qwen3/*", "meta-llama/*"]);
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_download_invalid() {
        assert!("unknown".parse::<DownloadPolicy>().is_err());
        assert!("allow()".parse::<DownloadPolicy>().is_err());
    }

    // -- DownloadPolicy logic -----------------------------------------------

    #[test]
    fn download_policy_allows() {
        assert!(DownloadPolicy::Eager.allows_download("anything"));
        assert!(!DownloadPolicy::Skip.allows_download("anything"));

        let allow = DownloadPolicy::Allow(vec!["Qwen3/*".into(), "meta-llama/*".into()]);
        assert!(allow.allows_download("Qwen3/Qwen3-0.6B"));
        assert!(allow.allows_download("meta-llama/Llama-3.1-8B"));
        assert!(!allow.allows_download("HuggingFaceTB/SmolLM2-135M"));
    }

    // -- ExecutePolicy parsing ----------------------------------------------

    #[test]
    fn parse_execute_eager() {
        let p: ExecutePolicy = "eager".parse().unwrap();
        assert!(matches!(p, ExecutePolicy::Eager));
        assert_eq!(p.to_string(), "eager");
    }

    #[test]
    fn parse_execute_skip() {
        let p: ExecutePolicy = "skip".parse().unwrap();
        assert!(matches!(p, ExecutePolicy::Skip));
    }

    #[test]
    fn parse_execute_allow_hf() {
        let p: ExecutePolicy = "allow(hf/Qwen3/*)".parse().unwrap();
        match &p {
            ExecutePolicy::Allow(pats) => {
                assert_eq!(pats.len(), 1);
                assert!(matches!(&pats[0], ExecutePattern::HuggingFace(s) if s == "Qwen3/*"));
            }
            _ => panic!("expected Allow"),
        }
        assert_eq!(p.to_string(), "allow(hf/Qwen3/*)");
    }

    #[test]
    fn parse_execute_allow_graph() {
        let p: ExecutePolicy = "allow(graph/abc123*)".parse().unwrap();
        match &p {
            ExecutePolicy::Allow(pats) => {
                assert_eq!(pats.len(), 1);
                assert!(matches!(&pats[0], ExecutePattern::Graph(s) if s == "abc123*"));
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_execute_allow_mixed() {
        let p: ExecutePolicy = "allow(hf/Qwen3/*,graph/abc*)".parse().unwrap();
        match &p {
            ExecutePolicy::Allow(pats) => {
                assert_eq!(pats.len(), 2);
                assert!(matches!(&pats[0], ExecutePattern::HuggingFace(s) if s == "Qwen3/*"));
                assert!(matches!(&pats[1], ExecutePattern::Graph(s) if s == "abc*"));
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_execute_invalid_namespace() {
        assert!("allow(unknown/foo)".parse::<ExecutePolicy>().is_err());
    }

    // -- ExecutePolicy logic ------------------------------------------------

    #[test]
    fn execute_policy_allows() {
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
