mod download;
mod execute;
mod glob;

pub use download::DownloadPolicy;
pub use execute::{ExecutePattern, ExecutePolicy};

fn parse_allow_patterns(policy: &str) -> Result<Vec<String>, String> {
    let trimmed = policy.trim();
    if !trimmed.starts_with("allow(") || !trimmed.ends_with(')') {
        return Err(format!("expected 'allow(pattern,...)' but got '{trimmed}'"));
    }

    let inner = &trimmed["allow(".len()..trimmed.len() - 1];
    let patterns: Vec<String> = inner
        .split(',')
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect();
    if patterns.is_empty() {
        return Err("allow() requires at least one pattern".to_string());
    }

    Ok(patterns)
}
