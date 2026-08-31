//! Build and inspect canonical causal-LM environments.
//!
//! Settings paths are local content-location hints only. They are resolved for
//! hashing and never enter the canonical bytes.

use anyhow::Context;
use clap::Subcommand;
use hellas_rpc::{
    CausalLmEnvironment, ContentId, ContentRef, MAX_CAUSAL_LM_ENVIRONMENT_BYTES, StaticSlice,
};
use hellas_store::ContentStore;
use serde::Deserialize;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::commands::CliResult;

const MAX_TEMPORARY_CREATE_ATTEMPTS: usize = 128;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Subcommand)]
pub enum EnvironmentCommand {
    /// Build a canonical causal-LM environment from Catena source and TOML settings.
    Build {
        /// Catena `.hex` source program to content-address. The provider's
        /// safe runtime compiles it only after an execution is authorized.
        #[arg(long, value_name = "CATENA_SOURCE")]
        program: PathBuf,
        /// TOML causal-LM ABI settings. Relative static-object paths are resolved
        /// beside this file but are not recorded in the environment.
        #[arg(long, value_name = "MODEL.toml")]
        settings: PathBuf,
        /// Canonical environment output. This is metadata, not a model archive.
        #[arg(long, value_name = "MODEL.environment")]
        out: PathBuf,
    },
    /// Strict-decode an environment and print its deterministic manifest identity.
    Inspect {
        /// Canonical environment file to inspect.
        #[arg(long, value_name = "FILE")]
        environment: PathBuf,
    },
    /// Prove that one environment and every object it references are locally available.
    Verify {
        /// Canonical environment whose complete local closure must be present.
        #[arg(long, value_name = "FILE")]
        environment: PathBuf,
        /// Individual local files to index. Repeat for multiple objects.
        #[arg(long = "content", value_name = "PATH")]
        content_paths: Vec<PathBuf>,
        /// Directory trees to adopt into the local content view. No network
        /// fetch is performed. Repeat for multiple roots.
        #[arg(long = "content-root", value_name = "DIR")]
        content_roots: Vec<PathBuf>,
        /// Optional fast-resume index to load and update after verification.
        #[arg(long = "content-index", value_name = "FILE")]
        content_index: Option<PathBuf>,
        /// Re-hash every local file instead of trusting fast-resume metadata.
        #[arg(long)]
        recheck: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentSettings {
    entrypoint: String,
    #[serde(default)]
    static_objects: Vec<PathBuf>,
    #[serde(default)]
    static_inputs: Vec<StaticInputSettings>,
    state_bytes_per_capacity: Vec<u64>,
    vocabulary_size: u64,
    maximum_capacity: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticInputSettings {
    object: u32,
    offset: u64,
    bytes: u64,
}

pub async fn run(command: EnvironmentCommand) -> CliResult {
    match command {
        EnvironmentCommand::Build {
            program,
            settings,
            out,
        } => build(&program, &settings, &out),
        EnvironmentCommand::Inspect { environment } => inspect(&environment),
        EnvironmentCommand::Verify {
            environment,
            content_paths,
            content_roots,
            content_index,
            recheck,
        } => verify(
            &environment,
            &content_paths,
            &content_roots,
            content_index.as_deref(),
            recheck,
        ),
    }
}

fn build(program_path: &Path, settings_path: &Path, out: &Path) -> CliResult {
    let settings_bytes = read_bounded_metadata(settings_path, "environment settings")?;
    let settings_text = std::str::from_utf8(&settings_bytes)
        .with_context(|| format!("settings {} are not valid UTF-8", settings_path.display()))?;
    let settings: EnvironmentSettings = toml::from_str(settings_text)
        .with_context(|| format!("failed to parse settings {}", settings_path.display()))?;
    let store = ContentStore::new();
    let program = index_ref(&store, program_path, "Catena program")?;
    let settings_dir = settings_path.parent().unwrap_or_else(|| Path::new("."));
    let objects = settings
        .static_objects
        .into_iter()
        .map(|path| {
            let path = if path.is_absolute() {
                path
            } else {
                settings_dir.join(path)
            };
            index_ref(&store, &path, "static object")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inputs = settings
        .static_inputs
        .into_iter()
        .map(|slice| StaticSlice::new(slice.object, slice.offset, slice.bytes))
        .collect();
    let environment = CausalLmEnvironment::new(
        program,
        settings.entrypoint,
        objects,
        inputs,
        settings.state_bytes_per_capacity,
        settings.vocabulary_size,
        settings.maximum_capacity,
    )
    .map_err(|error| anyhow::anyhow!("invalid causal-LM environment: {error}"))?;
    let bytes = environment.canonical_bytes();
    atomic_write(out, &bytes)?;
    print_environment(&environment, &bytes, out);
    Ok(())
}

fn inspect(path: &Path) -> CliResult {
    let bytes = read_bounded_metadata(path, "environment")?;
    let environment = CausalLmEnvironment::from_canonical_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid canonical environment: {error}"))?;
    print_environment(&environment, &bytes, path);
    Ok(())
}

/// Validate one concrete provider-ready causal-LM closure without compiling it
/// or touching the network. The environment path is a description of what to
/// check, not an implicit content source: it must also be present through a
/// configured `--content` or `--content-root`, exactly as it must be for
/// `serve`.
fn verify(
    environment_path: &Path,
    content_paths: &[PathBuf],
    content_roots: &[PathBuf],
    content_index: Option<&Path>,
    recheck: bool,
) -> CliResult {
    anyhow::ensure!(
        !content_paths.is_empty() || !content_roots.is_empty(),
        "environment verification requires at least one --content or --content-root"
    );

    let bytes = read_bounded_metadata(environment_path, "environment")?;
    let environment = CausalLmEnvironment::from_canonical_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid canonical environment: {error}"))?;
    let store = match (content_index, recheck) {
        (Some(index_path), false) => index_content(content_paths, content_roots, index_path)?,
        _ => populate_content(content_paths, content_roots, content_index, recheck)?,
    };

    require_local_content(
        &store,
        environment.content_id(),
        u64::try_from(bytes.len()).context("environment length does not fit u64")?,
        "environment",
    )?;
    require_local_content(
        &store,
        environment.program().id(),
        environment.program().bytes(),
        "program",
    )?;
    for (index, object) in environment.static_objects().iter().enumerate() {
        require_local_content(
            &store,
            object.id(),
            object.bytes(),
            &format!("static object {index}"),
        )?;
    }

    let manifest = environment.manifest();
    println!("ready       {}", manifest.content_id());
    println!("environment {}", environment.content_id());
    println!("program     {}", environment.program().id());
    println!("static objects {}", environment.static_objects().len());
    Ok(())
}

fn require_local_content(
    store: &ContentStore,
    id: ContentId,
    bytes: u64,
    label: &str,
) -> CliResult {
    let opened = store
        .open_verified(id.digest(), bytes)
        .with_context(|| format!("{label} {id} failed local verification"))?;
    anyhow::ensure!(opened.is_some(), "{label} {id} is not locally available");
    Ok(())
}

/// Read only bounded causal-LM metadata. Programs and static objects continue
/// through [`ContentStore`] and are never copied into this buffer.
fn read_bounded_metadata(path: &Path, label: &str) -> CliResult<Vec<u8>> {
    super::read_bounded_regular_file(path, label, MAX_CAUSAL_LM_ENVIRONMENT_BYTES)
}

fn index_ref(store: &ContentStore, path: &Path, label: &str) -> CliResult<ContentRef> {
    let indexed = store
        .index(path)
        .with_context(|| format!("failed to index {label} {}", path.display()))?;
    Ok(ContentRef::new(
        ContentId::from_bytes(*indexed.id.as_bytes()),
        indexed.len,
    ))
}

fn print_environment(environment: &CausalLmEnvironment, bytes: &[u8], path: &Path) {
    let manifest = environment.manifest();
    let manifest_bytes = manifest.canonical_bytes();
    println!(
        "environment {} ({} bytes) {}",
        ContentId::hash(bytes),
        bytes.len(),
        path.display()
    );
    println!(
        "manifest    {} ({} bytes)",
        ContentId::hash(&manifest_bytes),
        manifest_bytes.len()
    );
    println!(
        "application ({}, {})",
        manifest.application().evaluator(),
        manifest.application().adaptor()
    );
    println!("root        {}", manifest.root());
    println!(
        "program     {} {} bytes",
        environment.program().id(),
        environment.program().bytes()
    );
    for (index, object) in environment.static_objects().iter().enumerate() {
        println!("static[{index}]   {} {} bytes", object.id(), object.bytes());
    }
    println!("static inputs {}", environment.static_inputs().len());
    println!(
        "state bytes/capacity {:?}",
        environment.state_bytes_per_capacity()
    );
    println!("entrypoint  {}", environment.entrypoint());
    println!("vocabulary  {}", environment.vocabulary_size());
    println!("capacity    {}", environment.maximum_capacity());
}

/// Publish complete environment metadata and make both its bytes and directory
/// entry durable before reporting success. The operator must pre-create the
/// output parent and keep it and its ancestors stable and trusted while the
/// write runs; this function does not pretend that recursive directory creation
/// became crash-durable by syncing only the final leaf.
fn atomic_write(path: &Path, bytes: &[u8]) -> CliResult {
    use std::io::Write as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (temporary, mut file) = create_temporary(path, parent).with_context(|| {
        format!(
            "failed to create temporary output beside {}",
            path.display()
        )
    })?;
    let mut published = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        published = true;
        sync_directory(parent)?;
        Ok::<_, std::io::Error>(())
    })();
    if !published {
        let _ = std::fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to atomically write {}", path.display()))
}

fn create_temporary(path: &Path, parent: &Path) -> std::io::Result<(PathBuf, File)> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut last_collision = None;
    for _ in 0..MAX_TEMPORARY_CREATE_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(
            ".{}.{sequence}.environment.tmp",
            std::process::id()
        ));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique environment temporary file",
        )
    }))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(path)?
            .sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub fn index_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: &Path,
) -> CliResult<ContentStore> {
    populate_content(paths, roots, Some(index_path), false)
}

fn populate_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: Option<&Path>,
    recheck: bool,
) -> CliResult<ContentStore> {
    let store = ContentStore::new();
    let remembered = if recheck {
        0
    } else {
        index_path.map_or(0, |path| store.records().load(path))
    };
    for path in paths {
        store
            .index(path)
            .with_context(|| format!("failed to index local content {}", path.display()))?;
    }
    let mut adopted = 0usize;
    for root in roots {
        adopted += store
            .adopt(root)
            .with_context(|| format!("failed to adopt local content root {}", root.display()))?
            .len();
    }
    if let Some(index_path) = index_path {
        store
            .records()
            .save(index_path)
            .with_context(|| format!("failed to save content index {}", index_path.display()))?;
    }
    info!(
        remembered,
        indexed = store.len(),
        adopted,
        "indexed local content"
    );
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::{EnvironmentSettings, atomic_write, build, inspect};
    use super::{index_ref, verify};
    use hellas_rpc::{CausalLmEnvironment, ContentId, ContentRef};
    use hellas_store::ContentStore;
    use std::path::{Path, PathBuf};

    fn validate(settings: EnvironmentSettings, object_lengths: &[u64]) -> CausalLmEnvironment {
        let objects = object_lengths
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                ContentRef::new(ContentId::from_bytes([index as u8 + 2; 32]), *bytes)
            })
            .collect();
        CausalLmEnvironment::new(
            ContentRef::new(ContentId::from_bytes([1; 32]), 1),
            settings.entrypoint,
            objects,
            settings
                .static_inputs
                .into_iter()
                .map(|slice| hellas_rpc::StaticSlice::new(slice.object, slice.offset, slice.bytes))
                .collect(),
            settings.state_bytes_per_capacity,
            settings.vocabulary_size,
            settings.maximum_capacity,
        )
        .unwrap()
    }

    #[test]
    fn parses_human_toml_settings() {
        let settings: EnvironmentSettings = toml::from_str(
            r#"entrypoint = "model"
static_objects = ["weights.safetensors"]
state_bytes_per_capacity = [1024]
vocabulary_size = 32000
maximum_capacity = 4096

[[static_inputs]]
object = 0
offset = 8
bytes = 16
"#,
        )
        .unwrap();
        assert_eq!(settings.entrypoint, "model");
        assert_eq!(settings.static_inputs[0].object, 0);
    }

    #[test]
    fn rejects_unknown_human_settings() {
        let error = toml::from_str::<EnvironmentSettings>(
            r#"entrypoint = "model"
state_bytes_per_capacity = [1024]
vocabulary_size = 32000
maximum_capacity = 4096
unexpected = true
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn build_rejects_oversized_settings_before_indexing_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let settings = directory.path().join("oversized.toml");
        let output = directory.path().join("model.environment");
        std::fs::write(
            &settings,
            vec![0; hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1],
        )
        .unwrap();

        let error = build(&directory.path().join("missing.hex"), &settings, &output)
            .expect_err("oversized settings must be refused before artifact indexing");
        let message = error.to_string();
        assert!(message.contains("environment settings"), "{message}");
        assert!(message.contains("byte limit"), "{message}");
        assert!(!output.exists());
    }

    #[test]
    fn inspect_rejects_oversized_environment_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let environment = directory.path().join("oversized.environment");
        std::fs::write(
            &environment,
            vec![0; hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1],
        )
        .unwrap();

        let error = inspect(&environment).expect_err("oversized environment must be refused");
        let message = error.to_string();
        assert!(message.contains("environment"), "{message}");
        assert!(message.contains("byte limit"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_a_device_before_reading_from_it() {
        let error = inspect(Path::new("/dev/zero"))
            .expect_err("environment metadata must be an ordinary file");
        assert!(error.to_string().contains("failed to open environment"));
        assert!(format!("{error:#}").contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_output_does_not_follow_the_legacy_fixed_temporary_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("model.environment");
        let victim = directory.path().join("operator-data");
        let legacy_temporary = output.with_extension("tmp");
        std::fs::write(&victim, b"must survive").unwrap();
        symlink(&victim, &legacy_temporary).unwrap();

        atomic_write(&output, b"complete environment").unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"complete environment");
        assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");
        assert!(
            std::fs::symlink_metadata(&legacy_temporary)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn concurrent_atomic_outputs_publish_one_complete_private_file() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("model.environment");
        let publishers = 12_usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(publishers + 1));
        let mut threads = Vec::new();
        for marker in 1..=publishers {
            let payload = vec![u8::try_from(marker).unwrap(); marker * 4096];
            let output = output.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                atomic_write(&output, &payload)
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }

        let published = std::fs::read(&output).unwrap();
        let marker = usize::from(*published.first().expect("published file is not empty"));
        assert!((1..=publishers).contains(&marker));
        assert_eq!(
            published,
            vec![u8::try_from(marker).unwrap(); marker * 4096]
        );
        let final_name = output.file_name().unwrap().to_string_lossy();
        let temporary_prefix = format!(".{final_name}.");
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    !name.starts_with(&temporary_prefix) || !name.ends_with(".environment.tmp")
                }),
            "successful publication must clean every unique temporary"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn failed_atomic_output_removes_its_unique_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("model.environment");
        std::fs::create_dir(&output).unwrap();

        atomic_write(&output, b"cannot replace a directory")
            .expect_err("renaming a file over a directory must fail");

        let temporary_prefix = format!(".{}.", output.file_name().unwrap().to_string_lossy());
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    !name.starts_with(&temporary_prefix) || !name.ends_with(".environment.tmp")
                }),
            "failed publication left a unique temporary behind"
        );
    }

    #[test]
    fn atomic_output_requires_an_existing_parent() {
        let directory = tempfile::tempdir().unwrap();
        let missing_parent = directory.path().join("not-created");
        let output = missing_parent.join("model.environment");

        atomic_write(&output, b"complete environment")
            .expect_err("publication must not create an unsynced parent hierarchy");

        assert!(!missing_parent.exists());
        assert!(!output.exists());
    }

    #[test]
    fn checked_in_model_settings_match_the_pinned_generated_records() {
        // These identities pin every ordered static slice, not just the counts
        // below. Update them only when regenerating from the revision named in
        // each settings file.
        assert_eq!(
            ContentId::hash(include_bytes!(
                "../../../../examples/smollm2.environment.toml"
            ))
            .to_string(),
            "7add9e6a063fa47d467623023f904e2ea4cc2c4d42abbdca6168546b423d8073"
        );
        assert_eq!(
            ContentId::hash(include_bytes!(
                "../../../../examples/qwen3.environment.toml"
            ))
            .to_string(),
            "116674fd6e7e9aff0043ad18d32ffdea3de4985094efd004babbd26713fc5f30"
        );
        let smol: EnvironmentSettings = toml::from_str(include_str!(
            "../../../../examples/smollm2.environment.toml"
        ))
        .unwrap();
        assert_eq!(smol.entrypoint, "smollm2");
        assert_eq!(smol.static_objects.len(), 1);
        assert_eq!(smol.static_inputs.len(), 272);
        let smol = validate(smol, &[269_060_552]);
        assert_eq!(smol.vocabulary_size(), 49_152);
        assert_eq!(smol.maximum_capacity(), 8_192);

        let qwen: EnvironmentSettings =
            toml::from_str(include_str!("../../../../examples/qwen3.environment.toml")).unwrap();
        assert_eq!(qwen.entrypoint, "qwen3");
        assert_eq!(qwen.static_objects.len(), 2);
        assert_eq!(qwen.static_inputs.len(), 579);
        let qwen = validate(qwen, &[49_693_950_144, 11_401_853_280]);
        assert_eq!(qwen.vocabulary_size(), 151_936);
        assert_eq!(qwen.maximum_capacity(), 32_768);
    }

    fn provider_ready_environment(directory: &Path) -> PathBuf {
        let program_path = directory.join("model.hex");
        let weights_path = directory.join("weights.bin");
        std::fs::write(&program_path, b"fn model() { return; }").unwrap();
        std::fs::write(&weights_path, b"weights").unwrap();

        let store = ContentStore::new();
        let program = index_ref(&store, &program_path, "program").unwrap();
        let weights = index_ref(&store, &weights_path, "weights").unwrap();
        let environment = CausalLmEnvironment::new(
            program,
            "model",
            vec![weights],
            vec![hellas_rpc::StaticSlice::new(0, 0, weights.bytes())],
            vec![4],
            32,
            64,
        )
        .unwrap();
        let path = directory.join("model.environment");
        std::fs::write(&path, environment.canonical_bytes()).unwrap();
        path
    }

    #[test]
    fn verify_proves_a_complete_local_environment_closure() {
        let directory = tempfile::tempdir().unwrap();
        let environment = provider_ready_environment(directory.path());

        verify(
            &environment,
            &[],
            &[directory.path().to_path_buf()],
            None,
            false,
        )
        .unwrap();
    }

    #[test]
    fn verify_rejects_a_root_with_only_junk_or_an_incomplete_environment() {
        let directory = tempfile::tempdir().unwrap();
        let environment = provider_ready_environment(directory.path());
        std::fs::remove_file(directory.path().join("weights.bin")).unwrap();
        std::fs::write(directory.path().join("junk"), b"not model content").unwrap();

        let error = verify(
            &environment,
            &[],
            &[directory.path().to_path_buf()],
            None,
            false,
        )
        .expect_err("a missing referenced object must fail readiness");
        assert!(error.to_string().contains("static object 0"), "{error:#}");
        assert!(
            error.to_string().contains("not locally available"),
            "{error:#}"
        );
    }

    #[test]
    fn verify_does_not_treat_the_environment_argument_as_implicit_content() {
        let directory = tempfile::tempdir().unwrap();
        let environment = provider_ready_environment(directory.path());
        let empty = tempfile::tempdir().unwrap();

        let error = verify(
            &environment,
            &[],
            &[empty.path().to_path_buf()],
            None,
            false,
        )
        .expect_err("the provider content view must contain the environment itself");
        assert!(error.to_string().contains("environment"), "{error:#}");
        assert!(
            error.to_string().contains("not locally available"),
            "{error:#}"
        );
    }
}
