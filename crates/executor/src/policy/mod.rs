mod download;
mod execute;
mod glob;

pub use download::DownloadPolicy;
pub use execute::{ExecutePattern, ExecutePolicy};

fn parse_allow_patterns(policy: &str) -> Result<Vec<String>, String> {
    let trimmed = policy.trim();
    let inner = trimmed
        .strip_prefix("allow(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| format!("expected 'allow(pattern,...)' but got '{trimmed}'"))?;

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
