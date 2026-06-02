fn main() {
    #[cfg(feature = "compile")]
    compile();

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

#[cfg(feature = "compile")]
fn compile() {
    println!("cargo:rerun-if-changed=proto/*.proto");

    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.enable_type_names();

    tonic_prost_build::configure()
        .out_dir("src/pb")
        .include_file("mod.rs")
        .emit_package(true)
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .client_mod_attribute(".", "#[cfg(feature = \"client\")]")
        .server_mod_attribute(".", "#[cfg(feature = \"server\")]")
        .compile_with_config(prost_config, &["proto/light_client.proto"], &["proto"])
        .expect("failed to compile chain protos");
}
