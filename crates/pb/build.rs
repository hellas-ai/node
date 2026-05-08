fn main() {
    #[cfg(feature = "compile")]
    compile();
}

#[cfg(feature = "compile")]
fn compile() {
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/hellas.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/common.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/symbolic.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/opaque.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/ticket.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/execute.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/courtesy.proto");
    println!("cargo:rerun-if-changed=../../proto/hellas/v1/node.proto");

    let mut prost_config = tonic_prost_build::Config::new();
    prost_config.enable_type_names();

    tonic_prost_build::configure()
        .out_dir("src")
        .emit_package(true)
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .compile_with_config(
            prost_config,
            &[
                "../../proto/hellas/v1/common.proto",
                "../../proto/hellas/v1/symbolic.proto",
                "../../proto/hellas/v1/opaque.proto",
                "../../proto/hellas/v1/ticket.proto",
                "../../proto/hellas/v1/execute.proto",
                "../../proto/hellas/v1/courtesy.proto",
                "../../proto/hellas/v1/node.proto",
                "../../proto/hellas/v1/hellas.proto",
            ],
            &["../../proto"],
        )
        .expect("failed to compile Hellas protobuf definitions");
}
