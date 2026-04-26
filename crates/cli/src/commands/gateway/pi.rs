use std::process::Stdio;

use anyhow::Context;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::process::{Child, Command};

use crate::commands::CliResult;

const EXTENSION_TEMPLATE: &str = r#"export default function (pi) {
  pi.registerProvider("hellas", __PROVIDER__);
}
"#;

/// Spawned pi child + the tmpfile holding its extension. Drop both together —
/// the tempfile must outlive pi (it's read at startup), so we keep the handle
/// here. `Child` is configured with `kill_on_drop(true)` so a panicked /
/// cancelled gateway will tear pi down too.
pub struct PiHandle {
    pub child: Child,
    // Held so the tmpfile is only unlinked once pi has exited and we drop self.
    _extension: NamedTempFile,
}

pub fn spawn(
    base_url: &str,
    model: &str,
    api: &str,
    pi_bin: &str,
    pi_args: &[String],
) -> CliResult<PiHandle> {
    let provider = json!({
        "baseUrl": base_url,
        "apiKey": "unused",
        "api": api,
        "models": [{
            "id": model,
            "name": format!("{model} (Hellas)"),
            "reasoning": false,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 32768,
            "maxTokens": 2048,
        }],
    });
    let body = EXTENSION_TEMPLATE.replace(
        "__PROVIDER__",
        &serde_json::to_string(&provider).expect("static json shape"),
    );

    let extension = tempfile::Builder::new()
        .prefix("hellas-pi-")
        .suffix(".js")
        .tempfile()
        .context("failed to create pi extension tempfile")?;
    std::fs::write(extension.path(), body).context("failed to write pi extension")?;

    let child = Command::new(pi_bin)
        .arg("-e")
        .arg(extension.path())
        .args(["--provider", "hellas", "--model", model])
        .args(pi_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn `{pi_bin}`"))?;

    Ok(PiHandle {
        child,
        _extension: extension,
    })
}
