use std::fmt;
use std::str::FromStr;

use super::glob;

/// Controls which exact execution-environment identities a node will run.
#[derive(Clone, Debug, Default)]
pub enum ExecutePolicy {
    /// Run any supported environment (default).
    #[default]
    Any,
    /// Run environments whose hexadecimal content IDs match one of these
    /// globs.
    Only(Vec<String>),
    /// Refuse all evaluate execution.
    Deny,
}

impl ExecutePolicy {
    /// Returns whether `execution_environment` is admitted by this policy.
    #[must_use]
    pub fn allows_environment(&self, execution_environment: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(patterns) => patterns
                .iter()
                .any(|pattern| glob::matches(pattern, execution_environment)),
            Self::Deny => false,
        }
    }
}

impl FromStr for ExecutePolicy {
    type Err = String;

    fn from_str(policy: &str) -> Result<Self, Self::Err> {
        match policy {
            "any" => Ok(Self::Any),
            "none" => Ok(Self::Deny),
            _ if policy.starts_with("only(") => {
                let inner = policy
                    .strip_prefix("only(")
                    .and_then(|value| value.strip_suffix(')'))
                    .ok_or_else(|| format!("invalid execute policy {policy:?}"))?;
                let patterns = inner
                    .split(',')
                    .map(validate_pattern)
                    .collect::<Result<Vec<_>, _>>()?;
                if patterns.is_empty() {
                    return Err("only() requires at least one ID glob".to_string());
                }
                Ok(Self::Only(patterns))
            }
            _ => Err(format!(
                "invalid execute policy {policy:?}: expected 'any', 'none', or 'only(ID_GLOB,...)'"
            )),
        }
    }
}

fn validate_pattern(pattern: &str) -> Result<String, String> {
    if pattern.is_empty() {
        return Err("execution-environment ID globs must not be empty".to_string());
    }
    if pattern.len() > 64
        || !pattern
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'*'))
    {
        return Err(format!(
            "invalid execution-environment ID glob {pattern:?}: use at most 64 lowercase hexadecimal digits and '*'"
        ));
    }
    Ok(pattern.to_string())
}

impl fmt::Display for ExecutePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Deny => f.write_str("none"),
            Self::Only(patterns) => write!(f, "only({})", patterns.join(",")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutePolicy;

    const MATCHING: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn policies_round_trip_and_match_only_environment_ids() {
        for text in ["any", "none", "only(0123*,abcd)"] {
            let policy: ExecutePolicy = text.parse().unwrap();
            assert_eq!(policy.to_string(), text);
        }

        assert!(ExecutePolicy::Any.allows_environment(MATCHING));
        assert!(!ExecutePolicy::Deny.allows_environment(MATCHING));
        let only: ExecutePolicy = "only(0123*,abcd)".parse().unwrap();
        assert!(only.allows_environment(MATCHING));
        assert!(!only.allows_environment(OTHER));
    }

    #[test]
    fn old_alias_namespaces_and_empty_lists_are_rejected() {
        for text in [
            "eager",
            "skip",
            "allow(id/0123*)",
            "only(package/model)",
            "only()",
            " none ",
            "only(0123*, abcd)",
            "only( 0123*,abcd)",
        ] {
            assert!(text.parse::<ExecutePolicy>().is_err(), "accepted {text:?}");
        }
    }
}
