use std::collections::HashMap;
use thiserror::Error;

use crate::weights::WeightsLocator;
pub use hellas_rpc::pb::hellas::ExecutionStatus;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("quote not found: {0}")]
    QuoteNotFound(String),
    #[error("execution not found: {0}")]
    ExecutionNotFound(String),
}

#[derive(Clone)]
pub struct ExecutionPlan {
    pub graph: Vec<u8>,
    pub model_config_json: Vec<u8>,
    pub weights_key: WeightsLocator,
    pub input: Vec<u8>,
    pub prompt_tokens: u32,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}

pub struct Quote {
    pub plan: ExecutionPlan,
}

pub struct Execution {
    pub status: ExecutionStatus,
    pub progress: u64,
    pub result: Option<Vec<u8>>,
}

pub struct ExecutorState {
    quotes: HashMap<String, Quote>,
    executions: HashMap<String, Execution>,
    next_quote_id: u64,
    next_execution_id: u64,
}

impl ExecutorState {
    pub fn new() -> Self {
        Self {
            quotes: HashMap::new(),
            executions: HashMap::new(),
            next_quote_id: 0,
            next_execution_id: 0,
        }
    }

    pub fn create_quote(&mut self, plan: ExecutionPlan) -> String {
        let quote_id = format!("quote-{}", self.next_quote_id);
        self.next_quote_id += 1;
        self.quotes.insert(quote_id.clone(), Quote { plan });
        quote_id
    }

    pub fn get_quote(&self, quote_id: &str) -> Result<&Quote, StateError> {
        self.quotes
            .get(quote_id)
            .ok_or_else(|| StateError::QuoteNotFound(quote_id.to_string()))
    }

    pub fn create_execution(&mut self, quote_id: String) -> Result<String, StateError> {
        if !self.quotes.contains_key(&quote_id) {
            return Err(StateError::QuoteNotFound(quote_id));
        }
        let execution_id = format!("exec-{}", self.next_execution_id);
        self.next_execution_id += 1;
        self.executions.insert(
            execution_id.clone(),
            Execution {
                status: ExecutionStatus::Pending,
                progress: 0,
                result: None,
            },
        );
        Ok(execution_id)
    }

    pub fn get_execution(&self, execution_id: &str) -> Result<&Execution, StateError> {
        self.executions
            .get(execution_id)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn get_status(&self, execution_id: &str) -> Result<&ExecutionStatus, StateError> {
        Ok(&self.get_execution(execution_id)?.status)
    }

    pub fn get_result(&self, execution_id: &str) -> Result<&[u8], StateError> {
        self.get_execution(execution_id)?
            .result
            .as_deref()
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn get_progress(&self, execution_id: &str) -> Result<u64, StateError> {
        Ok(self.get_execution(execution_id)?.progress)
    }

    pub fn set_status(
        &mut self,
        execution_id: &str,
        status: ExecutionStatus,
    ) -> Result<(), StateError> {
        self.executions
            .get_mut(execution_id)
            .map(|exec| exec.status = status)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn set_result(&mut self, execution_id: &str, result: Vec<u8>) -> Result<(), StateError> {
        self.executions
            .get_mut(execution_id)
            .map(|exec| {
                exec.result = Some(result);
            })
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn append_output_chunk(
        &mut self,
        execution_id: &str,
        chunk: &[u8],
        progress: u64,
    ) -> Result<(), StateError> {
        let exec = self
            .executions
            .get_mut(execution_id)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))?;

        exec.progress = progress;

        if !chunk.is_empty() {
            exec.result
                .get_or_insert_with(Vec::new)
                .extend_from_slice(chunk);
        }

        Ok(())
    }
}

impl Default for ExecutorState {
    fn default() -> Self {
        Self::new()
    }
}
