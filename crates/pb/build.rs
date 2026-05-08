fn main() {
    #[cfg(feature = "compile")]
    {
        use std::path::Path;
        const PROTO_ROOT: &str = "../../proto";

        let pattern = format!("{PROTO_ROOT}/hellas/**/*.proto");
        let mut protos = glob::glob(&pattern)
            .expect("invalid proto glob")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to read proto glob");
        protos.sort();

        for proto in &protos {
            println!("cargo:rerun-if-changed={}", proto.display());
        }

        let mut prost_config = tonic_prost_build::Config::new();
        prost_config.enable_type_names();

        let proto_refs = protos
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect::<Vec<_>>();

        tonic_prost_build::configure()
            .out_dir("src")
            .emit_package(true)
            .build_client(true)
            .build_server(true)
            .build_transport(false)
            .compile_with_config(prost_config, &proto_refs, &[Path::new(PROTO_ROOT)])
            .expect("failed to compile Hellas protobuf definitions");
    }
}
