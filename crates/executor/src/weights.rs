use crate::backend::{create_backend, ExecBackend};
use crate::policy::DownloadPolicy;
use crate::ExecutorError;
use catgrad::interpreter::{self};
use catgrad::typecheck;
use catgrad_llm::utils::{get_model_chat_template, get_model_files, load_model};
use hf_hub::Cache;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokenizers::Tokenizer;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

const DEFAULT_REF: &str = "main";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModelRevision(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedWeightKey {
    pub model_id: ModelId,
    pub revision: ModelRevision,
}

#[derive(Clone)]
pub struct ModelBundle {
    pub key: ResolvedWeightKey,
    pub config: serde_json::Value,
    pub tokenizer: Tokenizer,
    pub chat_template: Option<String>,
    pub parameter_values: interpreter::Parameters<ExecBackend>,
    pub parameter_types: typecheck::Parameters,
}

#[derive(Clone, Debug)]
pub enum EnsureDisposition {
    Ready(ResolvedWeightKey),
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
    Downloading { revision: Option<ModelRevision> },
    Ready { revision: ModelRevision },
    Failed { error: String },
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct WeightsSnapshot {
    pub per_model: HashMap<ModelId, WeightsStatus>,
    pub active: Option<ModelId>,
    pub queue: Vec<ModelId>,
}

#[derive(Clone)]
pub struct WeightsManager {
    tx: mpsc::UnboundedSender<Command>,
}

#[allow(dead_code)]
enum Command {
    EnsureDefaultReady {
        model_id: ModelId,
        reply: oneshot::Sender<EnsureDisposition>,
    },
    WaitDefaultReady {
        model_id: ModelId,
        reply: oneshot::Sender<Result<ResolvedWeightKey, WeightsError>>,
    },
    Bundle {
        key: ResolvedWeightKey,
        reply: oneshot::Sender<Result<Arc<ModelBundle>, WeightsError>>,
    },
    Snapshot {
        reply: oneshot::Sender<WeightsSnapshot>,
    },
}

enum JobEvent {
    Resolved {
        model_id: ModelId,
        revision: ModelRevision,
    },
    Completed {
        model_id: ModelId,
        revision: ModelRevision,
        bundle: Arc<ModelBundle>,
    },
    Failed {
        model_id: ModelId,
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
    entries: HashMap<ModelId, Entry>,
    active: Option<ModelId>,
    queue: VecDeque<ModelId>,
    waiters: HashMap<ModelId, Vec<oneshot::Sender<Result<ResolvedWeightKey, WeightsError>>>>,
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

    pub async fn ensure_default_ready(&self, model_id: ModelId) -> EnsureDisposition {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(Command::EnsureDefaultReady {
                model_id,
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

    pub async fn ensure_default_ready_wait(
        &self,
        model_id: ModelId,
        wait_timeout: Duration,
    ) -> Result<ResolvedWeightKey, WeightsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::WaitDefaultReady {
                model_id,
                reply: reply_tx,
            })
            .map_err(|_| WeightsError::ManagerClosed)?;

        match timeout(wait_timeout, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(WeightsError::ManagerClosed),
            Err(_) => Err(WeightsError::NotReady),
        }
    }

    pub async fn bundle(&self, key: &ResolvedWeightKey) -> Result<Arc<ModelBundle>, WeightsError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::Bundle {
                key: key.clone(),
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

pub fn default_ref_cached(model_id: &str) -> bool {
    let repo = Cache::default().model(model_id.to_string());
    let has_config = repo.get("config.json").is_some();
    let has_tokenizer = repo.get("tokenizer.json").is_some();
    let has_weights = repo.get("model.safetensors").is_some()
        || repo.get("model.safetensors.index.json").is_some();
    has_config && has_tokenizer && has_weights
}

fn handle_command(state: &mut ManagerState, cmd: Command, job_tx: mpsc::UnboundedSender<JobEvent>) {
    match cmd {
        Command::EnsureDefaultReady { model_id, reply } => {
            let disposition = ensure_default_ready_disposition(state, &model_id, &job_tx);
            let _ = reply.send(disposition);
        }
        Command::WaitDefaultReady { model_id, reply } => {
            let disposition = ensure_default_ready_disposition(state, &model_id, &job_tx);
            match disposition {
                EnsureDisposition::Ready(key) => {
                    let _ = reply.send(Ok(key));
                }
                EnsureDisposition::Failed(error) => {
                    let _ = reply.send(Err(WeightsError::Failed(error)));
                }
                EnsureDisposition::Queued | EnsureDisposition::InFlight => {
                    let waiters = state.waiters.entry(model_id).or_default();
                    waiters.retain(|waiter| !waiter.is_closed());
                    waiters.push(reply);
                }
            }
        }
        Command::Bundle { key, reply } => {
            let entry = state.entries.get(&key.model_id);
            let result = match entry.map(|e| (&e.status, &e.bundle)) {
                Some((WeightsStatus::Ready { revision }, Some(bundle)))
                    if *revision == key.revision =>
                {
                    Ok(bundle.clone())
                }
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
                per_model: state
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

fn ensure_default_ready_disposition(
    state: &mut ManagerState,
    model_id: &ModelId,
    job_tx: &mpsc::UnboundedSender<JobEvent>,
) -> EnsureDisposition {
    // If the model already has an entry, follow existing logic — it has
    // already been admitted.
    if let Some(entry) = state.entries.get(model_id) {
        return match &entry.status {
            WeightsStatus::Ready { revision } => EnsureDisposition::Ready(ResolvedWeightKey {
                model_id: model_id.clone(),
                revision: revision.clone(),
            }),
            WeightsStatus::Failed { error } => {
                if !state.queue.contains(model_id) && state.active.as_ref() != Some(model_id) {
                    // Re-check policy before re-queuing a previously failed model.
                    if !default_ref_cached(&model_id.0)
                        && !state.download_policy.allows_download(&model_id.0)
                    {
                        return EnsureDisposition::Failed(format!(
                            "download policy '{}' denied download for model '{}'",
                            state.download_policy, model_id.0
                        ));
                    }
                    let entry = state.entries.get_mut(model_id).unwrap();
                    entry.status = WeightsStatus::Queued;
                    state.queue.push_back(model_id.clone());
                    maybe_start_next(state, job_tx.clone());
                    EnsureDisposition::Queued
                } else {
                    EnsureDisposition::Failed(error.clone())
                }
            }
            WeightsStatus::Queued
            | WeightsStatus::Resolving
            | WeightsStatus::Downloading { .. } => {
                if !state.queue.contains(model_id) && state.active.as_ref() != Some(model_id) {
                    state.queue.push_back(model_id.clone());
                    maybe_start_next(state, job_tx.clone());
                    EnsureDisposition::Queued
                } else {
                    EnsureDisposition::InFlight
                }
            }
        };
    }

    // New model: check download policy before admitting. Locally cached models
    // always bypass the policy — they don't require a network download.
    if !default_ref_cached(&model_id.0) && !state.download_policy.allows_download(&model_id.0) {
        return EnsureDisposition::Failed(format!(
            "download policy '{}' denied download for model '{}'",
            state.download_policy, model_id.0
        ));
    }

    state.entries.insert(model_id.clone(), Entry::default());
    state.queue.push_back(model_id.clone());
    maybe_start_next(state, job_tx.clone());
    EnsureDisposition::Queued
}

fn notify_waiters(
    state: &mut ManagerState,
    model_id: &ModelId,
    result: Result<ResolvedWeightKey, WeightsError>,
) {
    let Some(waiters) = state.waiters.remove(model_id) else {
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
        JobEvent::Resolved { model_id, revision } => {
            let entry = state
                .entries
                .entry(model_id.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Downloading {
                revision: Some(revision),
            };
        }
        JobEvent::Completed {
            model_id,
            revision,
            bundle,
        } => {
            let entry = state
                .entries
                .entry(model_id.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Ready {
                revision: revision.clone(),
            };
            entry.bundle = Some(bundle);
            state.active = None;
            info!(model = model_id.0, revision = revision.0, "weights ready");
            let key = ResolvedWeightKey {
                model_id: model_id.clone(),
                revision: revision.clone(),
            };
            notify_waiters(state, &model_id, Ok(key));
        }
        JobEvent::Failed { model_id, error } => {
            let entry = state
                .entries
                .entry(model_id.clone())
                .or_insert_with(Entry::default);
            entry.status = WeightsStatus::Failed {
                error: error.clone(),
            };
            entry.bundle = None;
            state.active = None;
            warn!(model = model_id.0, error, "weights failed");
            notify_waiters(state, &model_id, Err(WeightsError::Failed(error.clone())));
        }
    }
}

fn maybe_start_next(state: &mut ManagerState, job_tx: mpsc::UnboundedSender<JobEvent>) {
    if state.active.is_some() {
        return;
    }

    let Some(model_id) = state.queue.pop_front() else {
        return;
    };

    state.active = Some(model_id.clone());
    if let Some(entry) = state.entries.get_mut(&model_id) {
        entry.status = WeightsStatus::Resolving;
    }

    info!(model = model_id.0, "weights ensure started");
    tokio::spawn(async move {
        let model_id2 = model_id.clone();
        let job_tx2 = job_tx.clone();
        let result = tokio::task::spawn_blocking(move || load_default_bundle(&model_id2, job_tx2))
            .await
            .map_err(|e| format!("weights worker join error: {e}"))
            .and_then(|r| r.map_err(|e| e.to_string()));

        match result {
            Ok(_) => {}
            Err(error) => {
                let _ = job_tx.send(JobEvent::Failed { model_id, error });
            }
        }
    });
}

fn load_default_bundle(
    model_id: &ModelId,
    job_tx: mpsc::UnboundedSender<JobEvent>,
) -> Result<(), ExecutorError> {
    let backend = create_backend();

    // Ensure at least config is present and derive the resolved snapshot SHA from its path.
    let (_weights, config_path, _tokenizer_path, _tok_config) =
        get_model_files(&model_id.0, DEFAULT_REF)?;
    let revision = extract_revision_from_snapshot_path(&config_path).ok_or_else(|| {
        ExecutorError::WeightsError(format!(
            "unexpected hf cache path (no snapshots/<sha>): {config_path:?}"
        ))
    })?;

    info!(
        model = model_id.0,
        revision = revision.0,
        "weights resolved"
    );
    let _ = job_tx.send(JobEvent::Resolved {
        model_id: model_id.clone(),
        revision: revision.clone(),
    });

    // Load full model weights + tokenizer + config into memory.
    let (parameter_values, parameter_types, config, tokenizer, _total_params) =
        load_model(&model_id.0, DEFAULT_REF, &backend)?;

    let chat_template = match get_model_chat_template(&model_id.0, DEFAULT_REF) {
        Ok(t) if !t.trim().is_empty() => Some(t),
        Ok(_) => None,
        Err(err) => {
            warn!(model = model_id.0, "failed to load chat template: {err}");
            None
        }
    };

    let key = ResolvedWeightKey {
        model_id: model_id.clone(),
        revision: revision.clone(),
    };
    let bundle = Arc::new(ModelBundle {
        key: key.clone(),
        config,
        tokenizer,
        chat_template,
        parameter_values,
        parameter_types,
    });

    let _ = job_tx.send(JobEvent::Completed {
        model_id: model_id.clone(),
        revision,
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
        assert!(snap.per_model.is_empty());
        assert!(snap.active.is_none());
        assert!(snap.queue.is_empty());

        let status = WeightsStatus::Downloading {
            revision: Some(ModelRevision("deadbeef".to_string())),
        };
        if let WeightsStatus::Downloading { revision } = status {
            assert_eq!(revision.unwrap().0, "deadbeef");
        }
    }
}
