use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("quote not found: {0}")]
    QuoteNotFound(String),
    #[error("execution not found: {0}")]
    ExecutionNotFound(String),
}

pub struct Quote {
    pub graph_id: String,
    pub amount: u64,
}

pub struct Execution {
    pub quote_id: String,
    pub status: ExecutionStatus,
    pub result: Option<String>,
}

pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl ExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
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

    pub fn create_quote(&mut self, graph_id: String, amount: u64) -> String {
        let quote_id = format!("quote-{}", self.next_quote_id);
        self.next_quote_id += 1;
        self.quotes.insert(quote_id.clone(), Quote { graph_id, amount });
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
                quote_id,
                status: ExecutionStatus::Pending,
                result: None,
            },
        );
        Ok(execution_id)
    }

    pub fn get_status(&self, execution_id: &str) -> Result<&ExecutionStatus, StateError> {
        self.executions
            .get(execution_id)
            .map(|e| &e.status)
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }

    pub fn get_result(&self, execution_id: &str) -> Result<&str, StateError> {
        self.executions
            .get(execution_id)
            .and_then(|e| e.result.as_deref())
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
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

    pub fn set_result(&mut self, execution_id: &str, result: String) -> Result<(), StateError> {
        self.executions
            .get_mut(execution_id)
            .map(|exec| exec.result = Some(result))
            .ok_or_else(|| StateError::ExecutionNotFound(execution_id.to_string()))
    }
}

impl Default for ExecutorState {
    fn default() -> Self {
        Self::new()
    }
}
