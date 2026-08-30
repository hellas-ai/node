use std::path::{Path, PathBuf};

use catena_runner::VerifiedPackage;

use crate::ExecutorError;

/// Owner-supplied location of one Catena execution package.
///
/// This value never crosses an RPC boundary. `package_dir` contains the
/// package manifests; `artifact_dir` is where Catena Runner may materialize
/// and verify the package's declared program and weight objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageSource {
    name: String,
    package_dir: PathBuf,
    artifact_dir: PathBuf,
}

impl PackageSource {
    pub fn new(
        name: impl Into<String>,
        package_dir: impl Into<PathBuf>,
        artifact_dir: impl Into<PathBuf>,
    ) -> Result<Self, ExecutorError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(ExecutorError::InvalidPackageSource(
                "package name must not be empty".to_string(),
            ));
        }
        if name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ExecutorError::InvalidPackageSource(format!(
                "package name {name:?} must contain only ASCII letters, digits, '.', '-', or '_'"
            )));
        }
        let package_dir = package_dir.into();
        if package_dir.as_os_str().is_empty() {
            return Err(ExecutorError::InvalidPackageSource(
                "package directory must not be empty".to_string(),
            ));
        }
        let artifact_dir = artifact_dir.into();
        if artifact_dir.as_os_str().is_empty() {
            return Err(ExecutorError::InvalidPackageSource(
                "package artifact directory must not be empty".to_string(),
            ));
        }
        Ok(Self {
            name,
            package_dir,
            artifact_dir,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn package_dir(&self) -> &Path {
        &self.package_dir
    }

    pub fn artifact_dir(&self) -> &Path {
        &self.artifact_dir
    }
}

pub(crate) fn fetch_verified_package(
    source: &PackageSource,
) -> Result<VerifiedPackage, ExecutorError> {
    let fetched =
        catena_runner::artifacts::fetch_package(source.package_dir(), source.artifact_dir())
            .map_err(|error| ExecutorError::PackageLoad(format!("{error:#}")))?;
    VerifiedPackage::verify(source.package_dir(), &fetched.resolution_path)
        .map_err(|error| ExecutorError::PackageLoad(format!("{error:#}")))
}

/// Fetch and verify an owner-selected Catena package, returning the exact
/// execution identity without compiling or running it.
///
/// This performs blocking filesystem and network work. Callers in an async
/// runtime should put it behind `spawn_blocking`.
pub fn verified_package_identity(
    source: &PackageSource,
) -> Result<hellas_rpc::ExecutionPackageId, ExecutorError> {
    let package = fetch_verified_package(source)?;
    Ok(hellas_rpc::ExecutionPackageId::from_bytes(
        *package.identity().as_bytes(),
    ))
}
