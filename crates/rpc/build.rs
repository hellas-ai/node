fn main() {
    #[cfg(feature = "compile")]
    compile();
}

#[cfg(feature = "compile")]
fn compile() {
    println!("cargo:rerun-if-changed=proto/*.proto");
    tonic_prost_build::configure()
        .out_dir("src/pb")
        .include_file("mod.rs")
        .emit_package(true)
        .build_client(cfg!(feature = "client"))
        .build_server(cfg!(feature = "server"))
        .build_transport(cfg!(feature = "transport"))
        .compile_protos(&["proto/hellas.proto"], &["proto"])
        .expect("Failed to compile protos");
}
