fn main() {
    #[cfg(feature = "compile")]
    compile();
}

#[cfg(feature = "compile")]
fn compile() {
    let protos = &[
        "proto/hellas.proto",
        // "proto/execute.proto",
        // "proto/node.proto",
    ];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    tonic_prost_build::configure()
        .out_dir("src/pb")
        .include_file("mod.rs")
        .build_client(cfg!(feature = "client"))
        .build_server(cfg!(feature = "server"))
        .compile_protos(protos, &["proto"])
        .expect("Failed to compile protos");
}
