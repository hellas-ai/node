fn main() {
    emit_git_rev();

    #[cfg(feature = "compile")]
    compile::regenerate(std::path::Path::new(
        &std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    ));
}

fn emit_git_rev() {
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
mod compile {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use proc_macro2::TokenStream;
    use quote::{ToTokens, format_ident, quote};

    /// One captured service, decoupled from `prost_build::Service` so the
    /// rendering code stays pure.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RpcService {
        package: String,
        name: String,
        methods: Vec<RpcMethod>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RpcMethod {
        service: String,
        name: String,
        /// Already-resolved Rust path (`::hellas_pb::swarm::...`). prost-build
        /// rewrites these via `Config::extern_path` before our generator runs.
        request: String,
        response: String,
        request_stream: bool,
        response_stream: bool,
    }

    pub fn regenerate(manifest_dir: &Path) {
        // Imports inside .proto files name siblings like `hellas/v1/hellas.proto`,
        // so the include root protoc walks must be `proto/`, not `proto/hellas/`.
        let proto_includes = manifest_dir.join("../../proto");
        let proto_search = proto_includes.join("hellas");
        let mut protos = Vec::new();
        collect_proto_files(&proto_search, &mut protos);
        protos.sort();

        for proto in &protos {
            println!("cargo:rerun-if-changed={}", proto.display());
        }

        // The Arc<Mutex> is just plumbing — prost-build runs its generator
        // single-threaded, but we need to recover the collected services
        // after `compile_protos` returns.
        let services: Arc<Mutex<Vec<RpcService>>> = Arc::new(Mutex::new(Vec::new()));
        let mut config = prost_build::Config::new();
        for (proto_pkg, rust_path) in pb_module_table() {
            config.extern_path(format!(".{proto_pkg}"), *rust_path);
        }
        config.service_generator(Box::new(RpcServiceCollector {
            services: services.clone(),
        }));

        // prost-build always emits per-package message files. We ignore them
        // (hellas-pb owns the message types) and steer the output to a
        // sentinel subdir of OUT_DIR that nothing `include!`s.
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
        let discard_dir = out_dir.join("prost-discard");
        fs::create_dir_all(&discard_dir).expect("failed to create prost-discard dir");
        config.out_dir(&discard_dir);

        config
            .compile_protos(&protos, &[proto_includes])
            .expect("prost-build failed to parse hellas .proto files");

        // prost-build keeps the boxed generator alive past compile_protos, so
        // unwrap is out — just clone the collected list out of the mutex.
        let services = services
            .lock()
            .expect("service collector mutex poisoned")
            .clone();

        let service_markers = render_service_markers(&services);
        let client_traits = render_client_traits(&services);

        let generated_dir = manifest_dir.join("src/generated");
        fs::create_dir_all(&generated_dir).expect("failed to create src/generated");
        fs::write(generated_dir.join("service_markers.rs"), service_markers)
            .expect("failed to write src/generated/service_markers.rs");
        fs::write(generated_dir.join("client_traits.rs"), client_traits)
            .expect("failed to write src/generated/client_traits.rs");
    }

    fn collect_proto_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_proto_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "proto") {
                out.push(path);
            }
        }
    }

    /// Bridges prost-build's `ServiceGenerator` callback to our `Vec<RpcService>`.
    /// We deliberately leave `buf` untouched so prost-build's per-package files
    /// only contain the discarded message types — nothing to mix-and-match.
    struct RpcServiceCollector {
        services: Arc<Mutex<Vec<RpcService>>>,
    }

    impl prost_build::ServiceGenerator for RpcServiceCollector {
        fn generate(&mut self, service: prost_build::Service, buf: &mut String) {
            // prost-build deletes per-package modules whose buffer is empty
            // after code generation, then later iterates the package list to
            // call `finalize_package`. The lookup panics for the deleted
            // entry. Since we extern_path every hellas package, the message
            // side never emits anything, so we must write *something* to
            // `buf` to keep the module alive long enough for prost-build's
            // own bookkeeping to complete. A comment line is the smallest
            // safe payload.
            buf.push_str("// captured by hellas-rpc/build.rs RpcServiceCollector\n");

            let methods = service
                .methods
                .iter()
                .map(|method| RpcMethod {
                    service: service.proto_name.clone(),
                    name: method.proto_name.clone(),
                    request: method.input_type.clone(),
                    response: method.output_type.clone(),
                    request_stream: method.client_streaming,
                    response_stream: method.server_streaming,
                })
                .collect();
            self.services
                .lock()
                .expect("service vec poisoned")
                .push(RpcService {
                    package: service.package.clone(),
                    name: service.proto_name.clone(),
                    methods,
                });
        }
    }

    fn render_service_markers(services: &[RpcService]) -> String {
        let method_counts = method_counts(services);

        let service_marker_impls = services.iter().map(|service| {
            let service_ident = format_ident!("{}Service", service.name);
            let service_name = format!("{}.{}", service.package, service.name);
            let alpn = format!("/{service_name}/1.0");
            let feature = feature_for_package(&service.package);
            // The iroh ALPN lives on `IrohServiceSpec` (a feature-gated trait
            // companion to the transport-independent `RpcService`), so the
            // codegen emits two impls per service when the iroh transport
            // feature is on.
            quote! {
                #[cfg(feature = #feature)]
                pub struct #service_ident;

                #[cfg(feature = #feature)]
                impl RpcService for #service_ident {
                    const NAME: &'static str = #service_name;
                }

                #[cfg(all(
                    feature = #feature,
                    any(feature = "iroh-client", feature = "iroh-server"),
                ))]
                impl crate::peers::IrohServiceSpec for #service_ident {
                    const ALPN: &'static str = #alpn;
                }

                #[cfg(feature = #feature)]
                impl tonic::server::NamedService for #service_ident {
                    const NAME: &'static str = <Self as RpcService>::NAME;
                }
            }
        });

        let method_module_imports = services.iter().map(|service| {
            let feature = feature_for_package(&service.package);
            let service_ident = format_ident!("{}Service", service.name);
            quote! {
                #[cfg(feature = #feature)]
                use super::#service_ident;
            }
        });

        let mut method_marker_impls: Vec<TokenStream> = Vec::new();
        for service in services {
            let feature = feature_for_package(&service.package);
            let service_ident = format_ident!("{}Service", service.name);
            let service_name = format!("{}.{}", service.package, service.name);
            for method in &service.methods {
                let method_ident_tok = format_ident!("{}", method_ident(method, &method_counts));
                let request_ty: syn::Type =
                    syn::parse_str(&method.request).expect("request type parses as Rust");
                let response_ty: syn::Type =
                    syn::parse_str(&method.response).expect("response type parses as Rust");
                let method_name = &method.name;
                let grpc_path = format!("/{service_name}/{method_name}");
                let request_streaming = method.request_stream;
                let response_streaming = method.response_stream;
                // Core marker carries only Service + NAME; gRPC wire details
                // (path, prost types, streaming flags) live on the
                // `GrpcMethodSpec` companion trait. This split keeps the core
                // marker codec-independent for future non-gRPC transports.
                method_marker_impls.push(quote! {
                    #[cfg(feature = #feature)]
                    pub struct #method_ident_tok;

                    #[cfg(feature = #feature)]
                    impl RpcMethod for #method_ident_tok {
                        type Service = #service_ident;
                        const NAME: &'static str = #method_name;
                    }

                    #[cfg(feature = #feature)]
                    impl crate::peers::GrpcMethodSpec for #method_ident_tok {
                        type Request = #request_ty;
                        type Response = #response_ty;
                        const GRPC_PATH: &'static str = #grpc_path;
                        const REQUEST_STREAMING: bool = #request_streaming;
                        const RESPONSE_STREAMING: bool = #response_streaming;
                    }
                });
            }
        }

        // RpcServiceSpec impls — the only string-keyed dispatch in the system.
        // Each service emits one match arm per method so the inbound admission
        // layer can translate a gRPC path into a typed RequestKind without any
        // call site ever spelling a method name as a string.
        let mut spec_impls: Vec<TokenStream> = Vec::new();
        for service in services {
            let service_ident = format_ident!("{}Service", service.name);
            let feature = feature_for_package(&service.package);
            let mut arms: Vec<TokenStream> = Vec::new();
            for method in &service.methods {
                let method_ident_tok = format_ident!("{}", method_ident(method, &method_counts));
                let constructor = if is_rate_limited(&service.package, &service.name, &method.name)
                {
                    format_ident!("rate_limited_method")
                } else {
                    format_ident!("account_method")
                };
                arms.push(quote! {
                    <methods::#method_ident_tok as crate::peers::GrpcMethodSpec>::GRPC_PATH
                        => Some(crate::peers::InboundRequestPolicy::#constructor::<methods::#method_ident_tok>()),
                });
            }
            spec_impls.push(quote! {
                #[cfg(feature = #feature)]
                impl crate::peers::RpcServiceSpec for #service_ident {
                    fn inbound_policy(path: &str) -> Option<crate::peers::InboundRequestPolicy> {
                        match path {
                            #(#arms)*
                            _ => None,
                        }
                    }
                }
            });
        }

        // Single source of truth: every service and every rate-limited
        // method known to the protocol, regardless of which features are
        // compiled in. Lets transport-layer code (e.g.
        // `PeerDirectory::default_service_aliases`) discover the universe
        // of services without redeclaring it.
        let known_service_entries: Vec<TokenStream> = services
            .iter()
            .map(|service| {
                let service_name = format!("{}.{}", service.package, service.name);
                let alpn = format!("/{service_name}/1.0");
                quote! {
                    KnownService {
                        name: #service_name,
                        alpn: #alpn,
                    }
                }
            })
            .collect();

        let rate_limited_entries: Vec<TokenStream> = services
            .iter()
            .flat_map(|service| {
                let service_name = format!("{}.{}", service.package, service.name);
                service.methods.iter().filter_map(move |method| {
                    if is_rate_limited(&service.package, &service.name, &method.name) {
                        let path = format!("/{service_name}/{}", method.name);
                        Some(quote! { #path })
                    } else {
                        None
                    }
                })
            })
            .collect();

        let tokens = quote! {
            #[allow(unused_imports)]
            use crate::peers::RpcService;

            /// A protocol-level service entry — its FQN and the iroh ALPN
            /// derived from it. Emitted for every `.proto` service the
            /// build script saw, regardless of whether the matching feature
            /// flag is enabled in this build.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct KnownService {
                pub name: &'static str,
                pub alpn: &'static str,
            }

            /// Catalogue of every service this crate knows about. The
            /// transport layer (peer-disclosure filters, ALPN registry,
            /// etc.) iterates this to avoid hardcoding service identities
            /// in multiple places.
            pub const KNOWN_SERVICES: &[KnownService] = &[
                #(#known_service_entries,)*
            ];

            /// gRPC paths of every method marked rate-limited at codegen
            /// time. The `RpcServiceSpec::inbound_policy` match arms use the
            /// same source-of-truth (the `is_rate_limited` table in
            /// build.rs); this list lets runtime callers inspect the policy
            /// without having to fabricate `InboundRequestPolicy` values.
            pub const KNOWN_RATE_LIMITED_METHODS: &[&'static str] = &[
                #(#rate_limited_entries,)*
            ];

            #(#service_marker_impls)*

            pub mod methods {
                #[allow(unused_imports)]
                use crate::peers::RpcMethod;

                #(#method_module_imports)*

                #(#method_marker_impls)*
            }

            #(#spec_impls)*
        };

        prepend_generated_header(format_tokens(tokens))
    }

    /// Per-method opt-in to *enforcement* (per-peer + global rate limit, deny
    /// when over). The default is `account_only` — observe but never reject.
    ///
    /// Methods that commit server-side resources on first call (quotes,
    /// writes, expensive streams) are rate-limited so a single peer can't
    /// flood admission. Methods that are cheap reads / observability stay
    /// account-only — they get tracked but not rejected. RunTicket is
    /// rate-limited even though the executor queue is the primary gate;
    /// belt-and-braces against admission flooding.
    fn is_rate_limited(package: &str, service: &str, method: &str) -> bool {
        matches!(
            (package, service, method),
            // Peer-disclosure flood gate.
            ("hellas.swarm.v1", "Node", "GetKnownPeers")
            // Execute: ticket processing commits compute.
            | ("hellas.v1", "Execute", "RunTicket")
            // Quote endpoints: server commits to staging work.
            | ("hellas.opaque.v1", "Opaque", "CreateTicket")
            | ("hellas.symbolic.v1", "Symbolic", "CreateTicket")
            | ("hellas.courtesy.v1", "Courtesy", "QuotePreparedText")
            | ("hellas.courtesy.v1", "Courtesy", "QuotePrompt")
            | ("hellas.courtesy.v1", "Courtesy", "QuoteChatPrompt")
            // Writes: storage flooding.
            | ("hellas.courtesy.v1", "Courtesy", "PutArtifact")
            // Bidi-stream opens are expensive even if individual frames are
            // small.
            | ("hellas.courtesy.v1", "Courtesy", "DecodeTokens")
        )
    }

    fn feature_for_package(package: &str) -> &'static str {
        match package {
            "hellas.v1" => "execute",
            "hellas.courtesy.v1" => "courtesy",
            "hellas.opaque.v1" => "opaque",
            "hellas.swarm.v1" => "swarm",
            "hellas.symbolic.v1" => "symbolic",
            _ => panic!("no rpc-crate feature defined for protobuf package {package}"),
        }
    }

    /// Per-service extension trait + `impl <Trait> for IrohPeerHandle`.
    fn render_client_traits(services: &[RpcService]) -> String {
        let method_counts = method_counts(services);

        let service_blocks = services.iter().map(|service| {
            let trait_name = format_ident!("{}Client", service.name);
            let feature = feature_for_package(&service.package);

            let trait_methods = service
                .methods
                .iter()
                .map(|method| client_trait_method(method, &method_counts));
            let impl_methods = service
                .methods
                .iter()
                .map(|method| client_impl_method(method, &method_counts));

            quote! {
                #[cfg(all(feature = #feature, feature = "iroh-client"))]
                pub trait #trait_name {
                    #(#trait_methods)*
                }

                #[cfg(all(feature = #feature, feature = "iroh-client"))]
                impl #trait_name for crate::peers::IrohPeerHandle {
                    #(#impl_methods)*
                }
            }
        });

        let tokens = quote! {
            #(#service_blocks)*
        };

        prepend_generated_header(format_tokens(tokens))
    }

    fn client_trait_method(
        method: &RpcMethod,
        method_counts: &HashMap<String, usize>,
    ) -> TokenStream {
        let fn_name = format_ident!("{}", to_snake_case(&method.name));
        let request_arg = client_request_arg(method);
        let call_ty = call_type_for(method, method_counts);
        quote! {
            fn #fn_name(&self, request: #request_arg) -> #call_ty;
        }
    }

    fn client_impl_method(
        method: &RpcMethod,
        method_counts: &HashMap<String, usize>,
    ) -> TokenStream {
        let fn_name = format_ident!("{}", to_snake_case(&method.name));
        let request_arg = client_request_arg(method);
        let call_ty = call_type_for(method, method_counts);
        let call_prefix = format_ident!("{}", call_prefix(method));
        let marker_ident = format_ident!("{}", method_ident(method, method_counts));
        quote! {
            fn #fn_name(&self, request: #request_arg) -> #call_ty {
                crate::call::#call_prefix::<crate::service::methods::#marker_ident>::new(self.clone(), request)
            }
        }
    }

    fn client_request_arg(method: &RpcMethod) -> TokenStream {
        let request_ty: syn::Type =
            syn::parse_str(&method.request).expect("request type parses as Rust");
        if method.request_stream {
            quote! { impl tonic::IntoStreamingRequest<Message = #request_ty> }
        } else {
            quote! { impl tonic::IntoRequest<#request_ty> }
        }
    }

    fn call_type_for(method: &RpcMethod, method_counts: &HashMap<String, usize>) -> TokenStream {
        let prefix = format_ident!("{}", call_prefix(method));
        let marker_ident = format_ident!("{}", method_ident(method, method_counts));
        quote! { crate::call::#prefix<crate::service::methods::#marker_ident> }
    }

    fn call_prefix(method: &RpcMethod) -> &'static str {
        match (method.request_stream, method.response_stream) {
            (false, false) => "UnaryCall",
            (false, true) => "ServerStreamingCall",
            (true, false) => "ClientStreamingCall",
            (true, true) => "BidiStreamingCall",
        }
    }

    fn format_tokens(tokens: TokenStream) -> String {
        let file: syn::File = syn::parse2(tokens.clone()).unwrap_or_else(|err| {
            panic!(
                "generated tokens do not parse as a Rust file: {err}\n\n--- tokens ---\n{}\n",
                tokens.to_token_stream()
            )
        });
        prettyplease::unparse(&file)
    }

    fn prepend_generated_header(body: String) -> String {
        format!(
            "// @generated by `cargo build -p hellas-rpc --features compile`. \
             Do not edit by hand.\n\n{body}"
        )
    }

    fn method_counts(services: &[RpcService]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for service in services {
            for method in &service.methods {
                *counts.entry(method.name.clone()).or_insert(0) += 1;
            }
        }
        counts
    }

    fn method_ident(method: &RpcMethod, method_counts: &HashMap<String, usize>) -> String {
        if method_counts.get(&method.name).copied().unwrap_or(0) > 1 {
            format!("{}{}", method.service, method.name)
        } else {
            method.name.clone()
        }
    }

    /// Maps each hellas protobuf package to the Rust module path inside
    /// `hellas-pb` that owns its generated message types. `prost-build`'s
    /// `extern_path` consumes these so emitted method markers point straight
    /// at the pre-existing `hellas_pb::*` types instead of being re-generated.
    fn pb_module_table() -> &'static [(&'static str, &'static str)] {
        &[
            ("hellas.v1", "::hellas_pb::hellas"),
            ("hellas.swarm.v1", "::hellas_pb::swarm"),
            ("hellas.courtesy.v1", "::hellas_pb::courtesy"),
            ("hellas.opaque.v1", "::hellas_pb::opaque"),
            ("hellas.symbolic.v1", "::hellas_pb::symbolic"),
        ]
    }

    fn to_snake_case(input: &str) -> String {
        let mut output = String::new();
        let mut prev_lower_or_digit = false;
        for ch in input.chars() {
            if ch.is_ascii_uppercase() {
                if prev_lower_or_digit {
                    output.push('_');
                }
                output.push(ch.to_ascii_lowercase());
                prev_lower_or_digit = false;
            } else {
                output.push(ch);
                prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
            }
        }
        output
    }
}
