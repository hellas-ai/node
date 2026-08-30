use std::{path::PathBuf, str::FromStr};

#[cfg(feature = "evaluate")]
use anyhow::{Context, bail};
#[cfg(feature = "evaluate")]
use clap::Subcommand;
#[cfg(feature = "evaluate")]
use hellas_executor::PackageSource;
#[cfg(feature = "evaluate")]
use std::collections::BTreeSet;

#[cfg(feature = "evaluate")]
#[derive(Subcommand)]
pub enum PackageCommand {
    /// Fetch and verify a Catena package, then print its exact execution ID
    Id {
        /// Owner-selected package manifest, written NAME=PATH
        #[arg(long = "package", value_name = "NAME=PATH")]
        package: PackageArg,
        /// Directory for verified package objects (default: $HOME/.hellas/packages)
        #[arg(long = "package-cache")]
        package_cache: Option<PathBuf>,
    },
}

#[cfg(feature = "evaluate")]
pub async fn run(command: PackageCommand) -> anyhow::Result<()> {
    match command {
        PackageCommand::Id {
            package,
            package_cache,
        } => {
            let package_cache = package_cache
                .map(Ok)
                .unwrap_or_else(crate::identity::default_package_cache_path)?;
            let source = package.into_source(&package_cache)?;
            let identity = tokio::task::spawn_blocking(move || {
                hellas_executor::verified_package_identity(&source)
            })
            .await
            .context("Catena package verifier panicked")??;
            println!("{identity}");
            Ok(())
        }
    }
}

/// One Catena package alias, optionally paired with its manifest directory.
///
/// Remote callers use `NAME` together with a separate exact `--package-id`
/// pin: the peer resolves the opaque alias only as a routing convenience.
/// `NAME=PATH` additionally supplies the local manifest directory required by
/// `serve`, `--local`, and `--verify-local`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageArg {
    name: String,
    package_dir: Option<PathBuf>,
}

impl PackageArg {
    #[cfg(feature = "evaluate")]
    pub fn into_source(self, cache: &std::path::Path) -> anyhow::Result<PackageSource> {
        let package_dir = self.package_dir.ok_or_else(|| {
            anyhow::anyhow!(
                "Catena package {:?} needs a manifest path for local materialization; pass --package {}=PATH",
                self.name,
                self.name,
            )
        })?;
        let artifact_dir = cache.join(&self.name);
        PackageSource::new(self.name, package_dir, artifact_dir).map_err(anyhow::Error::from)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    #[cfg(any(feature = "evaluate", test))]
    pub fn package_dir(&self) -> Option<&std::path::Path> {
        self.package_dir.as_deref()
    }

    pub fn require_remote_alias(&self) -> Result<(), String> {
        if self.package_dir.is_some() {
            Err(format!(
                "remote Catena execution accepts only a package alias; pass --package {} without =PATH",
                self.name,
            ))
        } else {
            Ok(())
        }
    }

    #[cfg(any(feature = "evaluate", test))]
    pub fn artifact_dir(&self, cache: &std::path::Path) -> PathBuf {
        cache.join(&self.name)
    }
}

impl FromStr for PackageArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, directory) = match value.split_once('=') {
            Some((name, directory)) => (name, Some(directory)),
            None => (value, None),
        };
        let name = name.trim();
        let directory = directory.map(str::trim);
        if directory.is_some_and(str::is_empty) {
            return Err("package path must not be empty".to_string());
        }
        if name == "."
            || name == ".."
            || name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(
                "package name must contain only ASCII letters, digits, '.', '-', or '_'"
                    .to_string(),
            );
        }
        Ok(Self {
            name: name.to_string(),
            package_dir: directory.map(PathBuf::from),
        })
    }
}

#[cfg(feature = "evaluate")]
pub fn package_sources(
    packages: Vec<PackageArg>,
    cache: PathBuf,
) -> anyhow::Result<Vec<PackageSource>> {
    let mut names = BTreeSet::new();
    packages
        .into_iter()
        .map(|package| {
            if !names.insert(package.name().to_string()) {
                bail!(
                    "package alias {:?} is configured more than once",
                    package.name()
                );
            }
            package
                .into_source(&cache)
                .with_context(|| format!("invalid package below {}", cache.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_equals_path() {
        let package: PackageArg = "smollm2-135m=../catena-runner/models/smollm2"
            .parse()
            .unwrap();
        assert_eq!(package.name(), "smollm2-135m");
        assert_eq!(
            package.package_dir(),
            Some(std::path::Path::new("../catena-runner/models/smollm2"))
        );
        assert_eq!(
            package.artifact_dir(std::path::Path::new("cache")),
            std::path::Path::new("cache/smollm2-135m")
        );
    }

    #[test]
    fn parses_remote_alias_without_a_local_path() {
        let package: PackageArg = "smollm2-135m".parse().unwrap();
        assert_eq!(package.name(), "smollm2-135m");
        assert_eq!(package.package_dir(), None);
    }

    #[test]
    fn rejects_ambiguous_or_path_shaped_aliases_and_empty_paths() {
        for invalid in [
            "",
            " ",
            ".",
            "..",
            "owner/package",
            "=path",
            "name=",
            "name=   ",
        ] {
            assert!(
                invalid.parse::<PackageArg>().is_err(),
                "accepted invalid package argument {invalid:?}",
            );
        }
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn local_source_requires_a_manifest_path() {
        let package: PackageArg = "smollm2-135m".parse().unwrap();
        let error = package
            .into_source(std::path::Path::new("cache"))
            .unwrap_err();
        assert!(error.to_string().contains("smollm2-135m=PATH"));
    }

    #[test]
    fn remote_alias_rejects_a_local_manifest_path() {
        let local: PackageArg = "smollm2-135m=/packages/smollm2".parse().unwrap();
        assert!(local.require_remote_alias().is_err());
        let remote: PackageArg = "smollm2-135m".parse().unwrap();
        remote.require_remote_alias().unwrap();
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn rejects_duplicate_aliases() {
        let packages = vec!["x=one".parse().unwrap(), "x=two".parse().unwrap()];
        assert!(package_sources(packages, PathBuf::from("cache")).is_err());
    }
}
