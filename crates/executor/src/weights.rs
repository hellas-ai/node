use crate::backend::{create_backend, ExecBackend};
use crate::policy::DownloadPolicy;
use crate::ExecutorError;
use catgrad::interpreter::{self};
use catgrad::typecheck;
use catgrad_llm::utils::{get_model_files, load_model_weights};
use hf_hub::{Cache, Repo, RepoType};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

pub(crate) const DEFAULT_REF: &str = "main";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelRevision(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WeightsLocator {
    pub model_id: ModelId,
    pub revision: ModelRevision,
}

impl std::fmt::Display for WeightsLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.model_id.0, self.revision.0)
    }
}

#[derive(Clone)]
pub struct ModelBundle {
    pub parameter_values: interpreter::Parameters<ExecBackend>,
    pub parameter_types: typecheck::Parameters,
}

#[derive(Clone, Debug)]
pub enum EnsureDisposition {
    Ready,
    Queued,
    InFlight,
    Failed(String),
}

#[derive(Debug, Error, Clone)]
pub enum WeightsError {
    #[error("weights not ready")]
    NotReady,
    #[error("weights failed: {0}")]
    Failed(String),
    #[error("unknown weights key")]
    UnknownKey,
    #[error("weights manager closed")]
    ManagerClosed,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum WeightsStatus {
    Queued,
    Resolving,
    Downloading {
        resolved_revision: Option<ModelRevision>,
    },
    Ready {
        resolved_revision: ModelRevision,
    },
    Failed {
        error: String,
    },
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct WeightsSnapshot {
    pub per_locator: HashMap<WeightsLocator, WeightsStatus>,
    pub active: Option<WeightsLocator>,
    pub queue: Vec<WeightsLocator>,
}

#[derive(Clone)]
pub struct WeightsManager {
    tx: mpsc::UnboundedSender<Command>,
}

#[allow(dead_code)]
enum Command {
    EnsureReady {
        locator: WeightsLocator,
        reply: oneshot::Sender<EnsureDisposition>,
    },
    WaitReady {
        locator: WeightsLocator,
        reply: oneshot::Sender<Result<(), WeightsError>>,
    },
    Bundle {
        locator: WeightsLocator,
        reply: oneshot::Sender<Result<Arc<ModelBundle>, WeightsError>>,
    },
    Snapshot {
        reply: oneshot::Sender<WeightsSnapshot>,
    },
}

enum JobEvent {
    Resolved {
        locator: WeightsLocator,
        resolved_revision: ModelRevision,
    },
    Completed {
        locator: WeightsLocator,
        resolved_revision: ModelRevision,
        bundle: Arc<ModelBundle>,
    },
    Failed {
        locator: WeightsLocator,
        error: String,
    },
}

struct Entry {
    status: WeightsStatus,
    bundle: Option<Arc<ModelBundle>>,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            status: WeightsStatus::Queued,
            bundle: None,
        }
    }
}

struct ManagerState {
    entries: HashMap<WeightsLocator, Entry>,
    active: Option<WeightsLocator>,
    queue: VecDeque<WeightsLocator>,
    waiters: HashMap<WeightsLocator, Vec<oneshot::Sender<Result<(), WeightsError>>>>,
    download_policy: DownloadPolicy,
}

impl WeightsManager {
    pub fn spawn(download_policy: DownloadPolicy) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
        let (job_tx, mut job_rx) = mpsc::unbounded_channel::<JobEvent>();

        tokio::spawn(async move {
            let mut state = ManagerState {
                entries: HashMap::new(),
                active: None,
                queue: VecDeque::new(),
                waiters: HashMap::new(),
                download_policy,
            };

            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        let Some(cmd) = cmd else { break };
                        handle_command(&mut state, cmd, job_tx.clone());
                    }
                    evt = job_rx.recv() => {
                        let Some(evt) = evt else { break };
                        handle_job_event(&mut state, evt);
                        maybe_start_next(&mut state, job_tx.clone());
                    }
                }
            }
        });

        Self { tx }
    }

    pub async fn ensure_ready(&self, locator: WeightsLocator) -> EnsureDisposition {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(Command::EnsureReady {
                locator,
                reply: reply_tx,
            })
            .is_err()
        {
            return EnsureDisposition::Failed("weights manager closed".to_string());
        }
        reply_rx
            .await
            .unwrap_or_else(|_| EnsureDisposition::Failed("weights manager closed".to_string()))
    }

    pub async fn ensure_ready_wait(
        &self,
        locator: WeightsLocator,
        wait_timeout: Duration,
    ) -> Result<(), WeightsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::WaitReady {
                locator,
                reply: reply_tx,
            })
            .map_err(|_| WeightsError::ManagerClosed)?;

        match timeout(wait_timeout, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(WeightsError::ManagerClosed),
            Err(_) => Err(WeightsError::NotReady),
        }
    }

    pub async fn bundle(&self, locator: &WeightsLocator) -> Result<Arc<ModelBundle>, WeightsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::Bundle {
                locator: locator.clone(),
                reply: reply_tx,
            })
            .map_err(|_| WeightsError::ManagerClosed)?;
        reply_rx.await.map_err(|_| WeightsError::ManagerClosed)?
    }

    #[allow(dead_code)]
    pub async fn snapshot(&self) -> Result<WeightsSnapshot, WeightsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::Snapshot { reply: reply_tx })
            .map_err(|_| WeightsError::ManagerClosed)?;
        reply_rx.await.map_err(|_| WeightsError::ManagerClosed)
    }
}

pub fn weights_cached(locator: &WeightsLocator) -> bool {
    let repo = Cache::default().repo(Repo::with_revision(
        locator.model_id.0.clone(),
        RepoType::Model,
        locator.revision.0.clone(),
    ));
    let has_config = repo.get("config.json").is_some();
    let has_weights = repo.get("model.safetensors").is_some()
        || repo.get("model.safetensors.index.json").is_some();
    has_config && has_weights
}

fn handle_command(state: &mut ManagerState, cmd: Command, job_tx: mpsc::UnboundedSender<JobEvent>) {
    match cmd {
        Command::EnsureReady { locator, reply } => {
            let disposition = ensure_ready_disposition(state, &locator, &job_tx);
            let _ = reply.send(disposition);
        }
        Command::WaitReady { locator, reply } => {
            let disposition = ensure_ready_disposition(state, &locator, &job_tx);
            match disposition {
                EnsureDisposition::Ready => {
                    let _ = reply.send(Ok(()));
                }
                EnsureDisposition::Failed(error) => {
                    let _ = reply.send(Err(WeightsError::Failed(error)));
                }
                EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                    let waiters = state.waiters.entry(locator).or_default();
                    waiters.retain(|waiter| !waiter.is_closed());
                    waiters.push(reply);
                }
            }
        }
        Command::Bundle { locator, reply } => {
            let entry = state.entries.get(&locator);
            let result = match entry.map(|e| (&e.status, &e.bundle)) {
                Some((WeightsStatus::Ready { .. }, Some(bundle))) => Ok(bundle.clone()),
                Some((WeightsStatus::Ready { .. }, _)) => Err(WeightsError::UnknownKey),
                Some((WeightsStatus::Failed { error }, _)) => {
                    Err(WeightsError::Failed(error.clone()))
                }
                Some((_status, _)) => Err(WeightsError::NotReady),
                None => Err(WeightsError::UnknownKey),
            };
            let _ = reply.send(result);
        }
        Command::Snapshot { reply } => {
            let snapshot = WeightsSnapshot {
                per_locator: state
                    .entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.status.clone()))
                    .collect(),
                active: state.active.clone(),
                queue: state.queue.iter().cloned().collect(),
            };
            let _ = reply.send(snapshot);
        }
    }
}

fn ensure_ready_disposition(
    state: &mut ManagerState,
    locator: &WeightsLocator,
    job_tx: &mpsc::UnboundedSender<JobEvent>,
) -> EnsureDisposition {
    // If the locator already has an entry, follow existing logic — it has
    // already been admitted.
    if let Some(entry) = state.entries.get(locator) {
        return match &entry.status {
            WeightsStatus::Ready { .. } => EnsureDisposition::Ready,
            WeightsStatus::Failed { error } => {
                if !state.queue.contains(locator) && state.active.as_ref() != Some(locator) {
                    // Re-check policy before re-queuing a previously failed locator.
                    if !weights_cached(locator)
                        && !state.download_policy.allows_download(&locator.model_id.0)
                    {
                        return EnsureDisposition::Failed(format!(
                            "download policy '{}' denied download for weights '{}'",
                            state.download_policy, locator
                        ));
                    }
                    let entry = state.entries.get_mut(locator).unwrap();
                    entry.status = WeightsStatus::Queued;
                    state.queue.push_back(locator.clone());
                    maybe_start_next(state, job_tx.clone());
                    EnsureDisposition::Queued
                } else {
                    EnsureDisposition::Failed(error.clone())
                }
            }
            WeightsStatus::Queued
            | WeightsStatus::Resolving
            | WeightsStatus::Downloading { .. } => {
                if !state.queue.contains(locator) && state.active.as_ref() != Some(locator) {
                    state.queue.push_back(locator.clone());
                    maybe_start_next(state, job_tx.clone());
                    EnsureDisposition::Queued
                } else {
                    EnsureDisposition::InFlight
                }
            }
        };
    }

    // New locator: check download policy before admitting. Locally cached weights
    // always bypass the policy — they don't require a network download.
    if !weights_cached(locator) && !state.download_policy.allows_download(&locator.model_id.0) {
        return EnsureDisposition::Failed(format!(
            "download policy '{}' denied download for weights '{}'",
            state.download_policy, locator
        ));
    }

    state.entries.insert(locator.clone(), Entry::default());
    state.queue.push_back(locator.clone());
    maybe_start_next(state, job_tx.clone());
    EnsureDisposition::Queued
}

fn notify_waiters(
    state: &mut ManagerState,
    locator: &WeightsLocator,
    result: Result<(), WeightsError>,
) {
    let Some(waiters) = state.waiters.remove(locator) else {
        return;
    };

    for waiter in waiters {
        if waiter.is_closed() {
            continue;
        }
        let _ = waiter.send(result.clone());
    }
}

fn handle_job_event(state: &mut ManagerState, evt: JobEvent) {
    match evt {
        JobEvent::Resolved {
            locator,
            resolved_revision,
        } => {
            let entry = state
                .entries
                .entry(locator.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Downloading {
                resolved_revision: Some(resolved_revision),
            };
        }
        JobEvent::Completed {
            locator,
            resolved_revision,
            bundle,
        } => {
            let entry = state
                .entries
                .entry(locator.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Ready {
                resolved_revision: resolved_revision.clone(),
            };
            entry.bundle = Some(bundle);
            state.active = None;
            info!(
                model = locator.model_id.0,
                requested_revision = locator.revision.0,
                resolved_revision = resolved_revision.0,
                "weights ready"
            );
            notify_waiters(state, &locator, Ok(()));
        }
        JobEvent::Failed { locator, error } => {
            let entry = state
                .entries
                .entry(locator.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Failed {
                error: error.clone(),
            };
            entry.bundle = None;
            state.active = None;
            warn!(
                model = locator.model_id.0,
                requested_revision = locator.revision.0,
                error,
                "weights failed"
            );
            notify_waiters(state, &locator, Err(WeightsError::Failed(error.clone())));
        }
    }
}

fn maybe_start_next(state: &mut ManagerState, job_tx: mpsc::UnboundedSender<JobEvent>) {
    if state.active.is_some() {
        return;
    }

    let Some(locator) = state.queue.pop_front() else {
        return;
    };

    state.active = Some(locator.clone());
    if let Some(entry) = state.entries.get_mut(&locator) {
        entry.status = WeightsStatus::Resolving;
    }

    info!(
        model = locator.model_id.0,
        requested_revision = locator.revision.0,
        "weights ensure started"
    );
    tokio::spawn(async move {
        let locator2 = locator.clone();
        let job_tx2 = job_tx.clone();
        let result = tokio::task::spawn_blocking(move || load_bundle(&locator2, job_tx2))
            .await
            .map_err(|e| format!("weights worker join error: {e}"))
            .and_then(|r| r.map_err(|e| e.to_string()));

        match result {
            Ok(_) => {}
            Err(error) => {
                let _ = job_tx.send(JobEvent::Failed { locator, error });
            }
        }
    });
}

fn load_bundle(
    locator: &WeightsLocator,
    job_tx: mpsc::UnboundedSender<JobEvent>,
) -> Result<(), ExecutorError> {
    let backend = create_backend();

    // Ensure at least config is present and derive the resolved snapshot SHA from its path.
    let (model_paths, config_path, _tokenizer_path, _tok_config) =
        get_model_files(&locator.model_id.0, &locator.revision.0)?;
    let resolved_revision = extract_revision_from_snapshot_path(&config_path).ok_or_else(|| {
        ExecutorError::WeightsError(format!(
            "unexpected hf cache path (no snapshots/<sha>): {config_path:?}"
        ))
    })?;

    info!(
        model = locator.model_id.0,
        requested_revision = locator.revision.0,
        resolved_revision = resolved_revision.0,
        "weights resolved"
    );
    let _ = job_tx.send(JobEvent::Resolved {
        locator: locator.clone(),
        resolved_revision: resolved_revision.clone(),
    });

    let (parameter_values, parameter_types, _total_params) =
        load_model_weights(model_paths, &backend)?;
    let bundle = Arc::new(ModelBundle {
        parameter_values,
        parameter_types,
    });

    let _ = job_tx.send(JobEvent::Completed {
        locator: locator.clone(),
        resolved_revision,
        bundle,
    });
    Ok(())
}

fn extract_revision_from_snapshot_path(path: &Path) -> Option<ModelRevision> {
    let mut components = path.components().map(|c| c.as_os_str().to_string_lossy());
    while let Some(comp) = components.next() {
        if comp == "snapshots" {
            if let Some(sha) = components.next() {
                let sha = sha.to_string();
                if !sha.trim().is_empty() {
                    return Some(ModelRevision(sha));
                }
            }
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_revision_from_snapshot_path() {
        let p = PathBuf::from(
            "/x/.cache/huggingface/hub/models--foo--bar/snapshots/abcd1234/config.json",
        );
        assert_eq!(
            extract_revision_from_snapshot_path(&p).unwrap().0,
            "abcd1234"
        );
    }

    #[test]
    fn no_snapshot_segment_returns_none() {
        let p = PathBuf::from("/x/config.json");
        assert!(extract_revision_from_snapshot_path(&p).is_none());
    }

    #[tokio::test]
    async fn snapshot_is_available_without_network() {
        let weights = WeightsManager::spawn(DownloadPolicy::default());
        let snap = weights.snapshot().await.unwrap();
        assert!(snap.per_locator.is_empty());
        assert!(snap.active.is_none());
        assert!(snap.queue.is_empty());

        let status = WeightsStatus::Downloading {
            resolved_revision: Some(ModelRevision("deadbeef".to_string())),
        };
        if let WeightsStatus::Downloading { resolved_revision } = status {
            assert_eq!(resolved_revision.unwrap().0, "deadbeef");
        }
    }
}
