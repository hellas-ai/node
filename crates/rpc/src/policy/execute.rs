use std::fmt;
use std::str::FromStr;

use super::glob;
use super::parse_allow_patterns;

/// A namespaced pattern for Catena execution-package policy matching.
#[derive(Clone, Debug)]
pub enum ExecutePattern {
    /// `package/<glob>` matches on the locally configured package alias/name.
    Package(String),
    /// `id/<glob>` matches on the exact Catena execution package hex string.
    Id(String),
}

/// Controls which Catena execution packages the executor will run.
#[derive(Clone, Debug, Default)]
pub enum ExecutePolicy {
    /// Execute any package (default).
    #[default]
    Eager,
    /// Execute only packages matching one of the given patterns.
    Allow(Vec<ExecutePattern>),
    /// Refuse all executions.
    Skip,
}

impl ExecutePolicy {
    /// Returns `true` if this policy permits executing a Catena package with
    /// the given Catena execution package hex string and locally configured
    /// package name.
    pub fn allows_execute(&self, execution_package_id: &str, package_name: Option<&str>) -> bool {
        match self {
            Self::Eager => true,
            Self::Skip => false,
            Self::Allow(patterns) => patterns.iter().any(|pattern| match pattern {
                ExecutePattern::Package(pattern) => {
                    package_name.is_some_and(|name| glob::matches(pattern, name))
                }
                ExecutePattern::Id(pattern) => glob::matches(pattern, execution_package_id),
            }),
        }
    }

    /// Authorize a request that identifies only an exact execution package.
    ///
    /// Artifact-addressed evaluate requests carry no local alias, so a
    /// `package/...` rule cannot authorize them indirectly through whichever
    /// aliases happen to be loaded on this node.
    pub fn allows_execution_package(&self, execution_package_id: &str) -> bool {
        self.allows_execute(execution_package_id, None)
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
                "invalid execute policy '{trimmed}': expected 'eager', 'skip', or 'allow(package/pattern,...,id/pattern,...)'"
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
        if let Some(rest) = pattern.strip_prefix("package/") {
            if rest.is_empty() {
                return Err("package/ pattern must not be empty".to_string());
            }
            Ok(Self::Package(rest.to_string()))
        } else if let Some(rest) = pattern.strip_prefix("id/") {
            if rest.is_empty() {
                return Err("id/ pattern must not be empty".to_string());
            }
            Ok(Self::Id(rest.to_string()))
        } else {
            Err(format!(
                "execute pattern '{pattern}' must start with 'package/' or 'id/'"
            ))
        }
    }
}

impl fmt::Display for ExecutePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(pattern) => write!(f, "package/{pattern}"),
            Self::Id(pattern) => write!(f, "id/{pattern}"),
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
    fn parse_allow_package() {
        let policy: ExecutePolicy = "allow(package/qwen3-*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(
                    matches!(&patterns[0], ExecutePattern::Package(pattern) if pattern == "qwen3-*")
                );
            }
            _ => panic!("expected Allow"),
        }
        assert_eq!(policy.to_string(), "allow(package/qwen3-*)");
    }

    #[test]
    fn parse_allow_id() {
        let policy: ExecutePolicy = "allow(id/0123*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(matches!(&patterns[0], ExecutePattern::Id(pattern) if pattern == "0123*"));
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn parse_allow_mixed() {
        let policy: ExecutePolicy = "allow(package/qwen3-*,id/0123*)".parse().unwrap();
        match &policy {
            ExecutePolicy::Allow(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(
                    matches!(&patterns[0], ExecutePattern::Package(pattern) if pattern == "qwen3-*")
                );
                assert!(matches!(&patterns[1], ExecutePattern::Id(pattern) if pattern == "0123*"));
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
        let execution_package_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ExecutePolicy::Eager.allows_execute(execution_package_id, Some("any-package")));
        assert!(ExecutePolicy::Eager.allows_execute(execution_package_id, None));
        assert!(!ExecutePolicy::Skip.allows_execute(execution_package_id, Some("any-package")));

        let package_only = ExecutePolicy::Allow(vec![ExecutePattern::Package("qwen3-*".into())]);
        assert!(package_only.allows_execute("", Some("qwen3-30b-a3b")));
        assert!(!package_only.allows_execution_package(execution_package_id));
        assert!(!package_only.allows_execute("", Some("meta-llama/X")));
        assert!(!package_only.allows_execute("some-id", None));

        let id_only = ExecutePolicy::Allow(vec![ExecutePattern::Id("0123*".into())]);
        assert!(id_only.allows_execute(execution_package_id, None));
        assert!(id_only.allows_execution_package(execution_package_id));
        assert!(!id_only.allows_execute(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            None,
        ));
        assert!(id_only.allows_execute(execution_package_id, Some("anything")));

        let mixed = ExecutePolicy::Allow(vec![
            ExecutePattern::Package("qwen3-*".into()),
            ExecutePattern::Id("0123*".into()),
        ]);
        assert!(mixed.allows_execute("xyz", Some("qwen3-30b-a3b")));
        assert!(mixed.allows_execute(execution_package_id, Some("unknown-package")));
        assert!(!mixed.allows_execute(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            Some("unknown-package"),
        ));
    }
}
