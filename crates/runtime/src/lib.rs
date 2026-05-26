//! Hellas-owned runtime and commitment layer over upstream catgrad.

pub mod cid;
pub mod error;
pub mod graph;
pub mod runtime;
pub mod utils;

pub use catgrad::{category, interpreter, path, prelude, typecheck};
pub use catgrad_llm::{Detokenizer, PreparedPrompt, types};
pub use error::{LLMError, Result};
