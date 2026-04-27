use std::process::Stdio;

use anyhow::Context;
use tokio::process::{Child, Command};

use crate::commands::CliResult;

/// Spawn the wrapped command. The child inherits this process's stdio so
/// shell redirection on the wrapped command works as the user expects, and
/// is configured with `kill_on_drop(true)` so dropping the returned `Child`
/// (e.g. on gateway shutdown) tears it down too.
pub fn spawn(cmd: &str, args: &[String], base_url: &str) -> CliResult<Child> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .env("OPENAI_BASE_URL", format!("{base_url}/v1"))
        .env("ANTHROPIC_BASE_URL", base_url)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    // PR_SET_PDEATHSIG: if the gateway dies (panic / SIGKILL), the kernel
    // delivers SIGTERM to the wrapped child instead of stranding it as an
    // orphan. Linux-only; on macOS/BSD we rely on `kill_on_drop` for orderly
    // shutdown but a hard parent kill leaves the child running.
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Race window: if the parent already died between fork and prctl,
            // the signal will never fire. Re-check; bail if we're now reparented
            // to init.
            if libc::getppid() == 1 {
                libc::_exit(0);
            }
            Ok(())
        });
    }

    command
        .spawn()
        .with_context(|| format!("failed to spawn `{cmd}`"))
}

