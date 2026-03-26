fn main() {
    #[cfg(feature = "compile")]
    compile();

    // Capture git rev for version info.
    // Try git from this crate's own repo first (correct for cross-workspace path deps),
    // then fall back to GIT_REV env var (set by nix where git is unavailable).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let rev = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&manifest_dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if let Some(rev) = rev {
        println!("cargo:rustc-env=GIT_REV={rev}");
    } else if let Ok(rev) = std::env::var("GIT_REV") {
        println!("cargo:rustc-env=GIT_REV={rev}");
    }
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}

#[cfg(feature = "compile")]
fn compile() {
    println!("cargo:rerun-if-changed=proto/*.proto");
    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.enable_type_names();

    tonic_prost_build::configure()
        .out_dir("src/pb")
        .include_file("mod.rs")
        .emit_package(true)
        .build_client(cfg!(feature = "client"))
        .build_server(cfg!(feature = "server"))
        .build_transport(false) // we use our own transport
        .compile_with_config(prost_config, &["proto/hellas.proto"], &["proto"])
        .expect("Failed to compile protos");
}
