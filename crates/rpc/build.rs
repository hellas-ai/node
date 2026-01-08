fn main() {
    #[cfg(feature = "compile")]
    compile();
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
