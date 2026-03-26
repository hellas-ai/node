fn main() {
    #[cfg(feature = "compile")]
    compile();

    // Capture git rev for version info
    if std::env::var("GIT_REV").is_err() {
        if let Ok(output) = std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            && output.status.success()
        {
            let rev = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_REV={rev}");
        }
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
