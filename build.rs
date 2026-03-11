fn main() {
    // If GIT_REV is already set (e.g. by nix), don't override it.
    if std::env::var("GIT_REV").is_ok() {
        return;
    }
    // For local cargo builds, try to get the git revision.
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        && output.status.success()
    {
        let rev = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("cargo:rustc-env=GIT_REV={rev}");
    }
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
}
