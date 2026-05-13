use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
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

    generate_service_markers(Path::new(&manifest_dir));
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RpcMethod {
    service: String,
    name: String,
    request: String,
    response: String,
    request_stream: bool,
    response_stream: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RpcService {
    package: String,
    name: String,
    methods: Vec<RpcMethod>,
}

fn generate_service_markers(manifest_dir: &Path) {
    let proto_root = manifest_dir.join("../../proto/hellas");
    let mut protos = Vec::new();
    collect_proto_files(&proto_root, &mut protos);
    protos.sort();

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let services = protos
        .iter()
        .flat_map(|proto| parse_proto_services(proto))
        .collect::<Vec<_>>();
    let service_markers = render_service_markers(&services);
    let iroh_clients = render_iroh_clients(&services);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out_dir.join("service_markers.rs"), service_markers)
        .expect("failed to write generated service markers");
    fs::write(out_dir.join("iroh_clients.rs"), iroh_clients)
        .expect("failed to write generated iroh clients");
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

fn parse_proto_services(path: &Path) -> Vec<RpcService> {
    let source = fs::read_to_string(path).expect("proto file should be readable");
    let mut package = String::new();
    let mut services = Vec::new();
    let mut current: Option<RpcService> = None;

    for raw_line in source.lines() {
        let line = raw_line
            .split_once("//")
            .map_or(raw_line, |(prefix, _)| prefix)
            .trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("package ") {
            package = rest.trim_end_matches(';').trim().to_owned();
            continue;
        }

        if let Some(rest) = line.strip_prefix("service ") {
            let name = rest
                .split(|ch: char| ch == '{' || ch.is_whitespace())
                .find(|part| !part.is_empty())
                .expect("service name should be present")
                .to_owned();
            current = Some(RpcService {
                package: package.clone(),
                name,
                methods: Vec::new(),
            });
            continue;
        }

        if line.starts_with('}') {
            if let Some(service) = current.take() {
                services.push(service);
            }
            continue;
        }

        if let Some(service) = current.as_mut()
            && let Some(rest) = line.strip_prefix("rpc ")
        {
            let parsed = parse_rpc_method(rest);
            service.methods.push(RpcMethod {
                service: service.name.clone(),
                name: parsed.name,
                request: parsed.request,
                response: parsed.response,
                request_stream: parsed.request_stream,
                response_stream: parsed.response_stream,
            });
        }
    }

    if let Some(service) = current {
        services.push(service);
    }

    services
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRpcMethod {
    name: String,
    request: String,
    response: String,
    request_stream: bool,
    response_stream: bool,
}

fn parse_rpc_method(rest: &str) -> ParsedRpcMethod {
    let (name, after_name) = rest
        .split_once('(')
        .expect("rpc method should include request type");
    let name = name.trim().to_owned();
    let (request, after_request) = after_name
        .split_once(')')
        .expect("rpc method request should be closed");
    let after_returns = after_request
        .trim()
        .strip_prefix("returns")
        .expect("rpc method should include returns")
        .trim();
    let after_open = after_returns
        .strip_prefix('(')
        .expect("rpc return type should open with paren");
    let (response, _) = after_open
        .split_once(')')
        .expect("rpc return type should be closed");
    let (request_stream, request) = parse_stream_type(request);
    let (response_stream, response) = parse_stream_type(response);
    ParsedRpcMethod {
        name,
        request,
        response,
        request_stream,
        response_stream,
    }
}

fn parse_stream_type(raw: &str) -> (bool, String) {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix("stream ") {
        (true, rest.trim().to_owned())
    } else {
        (false, raw.to_owned())
    }
}

fn render_service_markers(services: &[RpcService]) -> String {
    let mut output = String::from(
        "// @generated by crates/rpc/build.rs. Do not edit by hand.\n\n\
         use crate::peers::ServiceKey;\n\n",
    );

    for service in services {
        let service_ident = service_ident(&service.name);
        let service_name = format!("{}.{}", service.package, service.name);
        output.push_str(&format!(
            "pub struct {service_ident};\n\n\
             impl ServiceKey for {service_ident} {{\n\
                 const NAME: &'static str = \"{service_name}\";\n\
             }}\n\n\
             impl tonic::server::NamedService for {service_ident} {{\n\
                 const NAME: &'static str = <Self as ServiceKey>::NAME;\n\
             }}\n\n",
        ));
    }

    let method_counts = method_counts(services);
    output.push_str("pub mod methods {\n");
    output.push_str("    use crate::peers::MethodKey;\n");
    for service in services {
        output.push_str(&format!(
            "    use super::{};\n",
            service_ident(&service.name)
        ));
    }
    output.push('\n');

    for service in services {
        let service_ident = service_ident(&service.name);
        for method in &service.methods {
            let method_ident = method_ident(method, &method_counts);
            output.push_str(&format!(
                "    pub struct {method_ident};\n\n\
                     impl MethodKey for {method_ident} {{\n\
                         type Service = {service_ident};\n\
                         const NAME: &'static str = \"{}\";\n\
                     }}\n\n",
                method.name
            ));
        }
    }

    output.push_str("}\n");
    output
}

fn render_iroh_clients(services: &[RpcService]) -> String {
    let mut output = String::from("// @generated by crates/rpc/build.rs. Do not edit by hand.\n\n");
    let method_counts = method_counts(services);

    for service in services {
        let service_ident = service_ident(&service.name);
        let wrapper_ident = format!("Iroh{}Client", service.name);
        let client_ident = format!("{}Client", service.name);
        let client_module = format!("{}_client", to_snake_case(&service.name));
        let pb_module = pb_module_for_package(&service.package);

        output.push_str(&format!(
            "#[derive(Clone, Debug)]\n\
             pub struct {wrapper_ident} {{\n\
                 pool: crate::peers::IrohRpcPool<crate::service::{service_ident}>,\n\
             }}\n\n\
             impl {wrapper_ident} {{\n\
                 #[must_use]\n\
                 pub fn new(\n\
                     endpoint: tonic_iroh_transport::iroh::Endpoint,\n\
                     manager: crate::peers::PeerManager,\n\
                     options: tonic_iroh_transport::PoolOptions,\n\
                 ) -> Self {{\n\
                     Self {{ pool: crate::peers::IrohRpcPool::new(endpoint, manager, options) }}\n\
                 }}\n\n\
                 #[must_use]\n\
                 pub fn from_pool(pool: crate::peers::IrohRpcPool<crate::service::{service_ident}>) -> Self {{\n\
                     Self {{ pool }}\n\
                 }}\n\n\
                 #[must_use]\n\
                 pub const fn pool(&self) -> &crate::peers::IrohRpcPool<crate::service::{service_ident}> {{\n\
                     &self.pool\n\
                 }}\n\n"
        ));

        for method in &service.methods {
            let fn_name = to_snake_case(&method.name);
            let with_cost_name = format!("{fn_name}_with_cost");
            let marker_ident = method_ident(method, &method_counts);
            let request_ty = rust_type(&service.package, &method.request);
            let response_ty = rust_type(&service.package, &method.response);
            let request_arg = if method.request_stream {
                format!("impl tonic::IntoStreamingRequest<Message = {request_ty}>")
            } else {
                format!("impl tonic::IntoRequest<{request_ty}>")
            };
            let return_ty = if method.response_stream {
                format!(
                    "Result<tonic::Response<crate::iroh_client::ManagedStreaming<{response_ty}>>, crate::iroh_client::IrohClientError>"
                )
            } else {
                format!(
                    "Result<tonic::Response<{response_ty}>, crate::iroh_client::IrohClientError>"
                )
            };
            let finish_fn = if method.response_stream {
                "finish_streaming"
            } else {
                "finish_unary"
            };

            output.push_str(&format!(
                "    pub async fn {fn_name}(\n\
                         &self,\n\
                         peer: tonic_iroh_transport::iroh::EndpointId,\n\
                         request: {request_arg},\n\
                     ) -> {return_ty} {{\n\
                         self.{with_cost_name}(peer, 1.0, request).await\n\
                     }}\n\n\
                     pub async fn {with_cost_name}(\n\
                         &self,\n\
                         peer: tonic_iroh_transport::iroh::EndpointId,\n\
                         cost: f32,\n\
                         request: {request_arg},\n\
                     ) -> {return_ty} {{\n\
                         let (channel, permit) = self\n\
                             .pool\n\
                             .channel::<crate::service::methods::{marker_ident}>(peer, cost)\n\
                             .await?;\n\
                         let mut client = hellas_pb::{pb_module}::{client_module}::{client_ident}::new(channel);\n\
                         crate::iroh_client::{finish_fn}::<crate::service::methods::{marker_ident}, _>(\n\
                             permit,\n\
                             client.{fn_name}(request).await,\n\
                         )\n\
                     }}\n\n"
            ));
        }

        output.push_str("}\n\n");
    }

    output
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

fn service_ident(service: &str) -> String {
    format!("{service}Service")
}

fn method_ident(method: &RpcMethod, method_counts: &HashMap<String, usize>) -> String {
    if method_counts.get(&method.name).copied().unwrap_or(0) > 1 {
        format!("{}{}", method.service, method.name)
    } else {
        method.name.clone()
    }
}

fn pb_module_for_package(package: &str) -> &'static str {
    match package {
        "hellas.v1" => "hellas",
        "hellas.courtesy.v1" => "courtesy",
        "hellas.opaque.v1" => "opaque",
        "hellas.swarm.v1" => "swarm",
        "hellas.symbolic.v1" => "symbolic",
        _ => panic!("unknown hellas protobuf package {package}"),
    }
}

fn rust_type(current_package: &str, raw: &str) -> String {
    let raw = raw.trim().trim_start_matches('.');
    let (package, ty) = if let Some((package, ty)) = raw.rsplit_once('.') {
        (package, ty)
    } else {
        (current_package, raw)
    };
    format!("hellas_pb::{}::{ty}", pb_module_for_package(package))
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
