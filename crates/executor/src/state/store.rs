use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::backend::ExecBackend;
use crate::weights::{CachedProgram, PrefixHash};
use catgrad_llm::Snapshot;
use thiserror::Error;
use uuid::Uuid;

use super::{ExecutionPlan, ExecutionStatus};

#[derive(Debug, Error)]
pub enum StateError {
    #[error("quote not found: {0}")]
    QuoteNotFound(String),
    #[error("quote expired: {0}")]
    QuoteExpired(String),
    #[error("execution not found: {0}")]
    ExecutionNotFound(String),
    #[error("output not available: {0}")]
    OutputNotAvailable(String),
}

#[derive(Clone)]
pub struct QuoteRecord {
    pub plan: ExecutionPlan,
    pub program: Arc<CachedProgram>,
    pub start_snapshot: Arc<Snapshot<ExecBackend>>,
    pub start_prefix_len: usize,
    pub start_prefix_hash: PrefixHash,
    pub start_next_token: Option<u32>,
    pub expires_at: Instant,
}

pub struct ExecutionSnapshot {
    pub status: ExecutionStatus,
    pub progress: u64,
    pub output: Vec<u8>,
}

struct ExecutionRecord {
    status: ExecutionStatus,
    progress: u64,
    output: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct ExecutorState {
    quotes: HashMap<String, QuoteRecord>,
    executions: HashMap<String, ExecutionRecord>,
}

impl ExecutorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_quote(&mut self, quote: QuoteRecord) -> String {
        let quote_id = make_id("quote");
        self.quotes.insert(quote_id.clone(), quote);
        quote_id
    }

    pub fn get_quote(&self, quote_id: &str, now: Instant) -> Result<&QuoteRecord, StateError> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| StateError::QuoteNotFound(quote_id.to_string()))?;
        if quote.expires_at <= now {
            return Err(StateError::QuoteExpired(quote_id.to_string()));
        }
        Ok(quote)
    }

    pub fn remove_quote(&mut self, quote_id: &str) -> Option<QuoteRecord> {
        self.quotes.remove(quote_id)
    }

    pub fn prune_expired_quotes(&mut self, now: Instant) -> usize {
        let before = self.quotes.len();
        self.quotes.retain(|_, quote| quote.expires_at > now);
        before - self.quotes.len()
    }

    pub fn create_execution(&mut self) -> String {
        let execution_id = make_id("exec");
        self.executions.insert(
            execution_id.clone(),
            ExecutionRecord {
                status: ExecutionStatus::Pending,
                progress: 0,
                output: None,
            },
        );
        execution_id
    }

    pub fn remove_execution(&mut self, execution_id: &str) -> Result<(), StateError> {
        self.executions
            .remove(execution_id)
            .map(|_| ())
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn snapshot(&self, execution_id: &str) -> Result<ExecutionSnapshot, StateError> {
        Ok(self.execution(execution_id)?.snapshot())
    }

    pub fn status_snapshot(
        &self,
        execution_id: &str,
    ) -> Result<(ExecutionStatus, u64), StateError> {
        let execution = self.execution(execution_id)?;
        Ok((execution.status, execution.progress))
    }

    pub fn status(&self, execution_id: &str) -> Result<ExecutionStatus, StateError> {
        Ok(self.execution(execution_id)?.status)
    }

    pub fn output(&self, execution_id: &str) -> Result<&[u8], StateError> {
        self.execution(execution_id)?
            .output
            .as_deref()
            .ok_or_else(|| StateError::OutputNotAvailable(execution_id.to_string()))
    }

    pub fn progress(&self, execution_id: &str) -> Result<u64, StateError> {
        Ok(self.execution(execution_id)?.progress)
    }

    pub fn mark_running(&mut self, execution_id: &str) -> Result<(), StateError> {
        self.execution_mut(execution_id)?.status = ExecutionStatus::Running;
        Ok(())
    }

    pub fn complete_execution(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
        output: Option<Vec<u8>>,
    ) -> Result<(), StateError> {
        let execution = self.execution_mut(execution_id)?;
        execution.status = status;

        if let Some(output) = output {
            execution.output = Some(output);
        } else if matches!(status, ExecutionStatus::Completed) {
            execution.output.get_or_insert_with(Vec::new);
        }

        Ok(())
    }

    pub fn append_output_chunk(
        &mut self,
        execution_id: &str,
        chunk: &[u8],
        progress: u64,
    ) -> Result<(), StateError> {
        let execution = self.execution_mut(execution_id)?;
        execution.progress = progress;
        if !chunk.is_empty() {
            execution
                .output
                .get_or_insert_with(Vec::new)
                .extend_from_slice(chunk);
        }
        Ok(())
    }

    fn execution(&self, execution_id: &str) -> Result<&ExecutionRecord, StateError> {
        self.executions
            .get(execution_id)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    fn execution_mut(&mut self, execution_id: &str) -> Result<&mut ExecutionRecord, StateError> {
        self.executions
            .get_mut(execution_id)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }
}

fn make_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

impl ExecutionRecord {
    fn snapshot(&self) -> ExecutionSnapshot {
        ExecutionSnapshot {
            status: self.status,
            progress: self.progress,
            output: self.output.clone().unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn append_output_chunk_accumulates_bytes_and_latest_progress(
            updates in vec((any::<u64>(), vec(any::<u8>(), 0..16)), 0..32)
        ) {
            let mut state = ExecutorState::new();
            let execution_id = state.create_execution();

            let mut expected_output = Vec::new();
            let mut expected_progress = 0;

            for (progress, chunk) in &updates {
                state.append_output_chunk(&execution_id, chunk, *progress).unwrap();
                expected_progress = *progress;
                expected_output.extend_from_slice(chunk);
            }

            let snapshot = state.snapshot(&execution_id).unwrap();
            prop_assert_eq!(snapshot.progress, expected_progress);
            prop_assert_eq!(snapshot.output, expected_output);
        }
    }

    #[test]
    fn snapshot_defaults_missing_output_to_empty() {
        let mut state = ExecutorState::new();
        let execution_id = state.create_execution();

        let snapshot = state.snapshot(&execution_id).unwrap();
        assert_eq!(snapshot.status, ExecutionStatus::Pending);
        assert_eq!(snapshot.progress, 0);
        assert!(snapshot.output.is_empty());
    }
}
