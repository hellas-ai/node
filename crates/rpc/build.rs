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

/// Brace- and string-aware scanner over a comment-stripped `.proto` source.
///
/// We only need enough proto3 to find `package`, `service`, and `rpc` decls;
/// everything else (messages, enums, options, nested types, method bodies)
/// is skipped past balanced braces with string-literal awareness so that
/// neither `option some.key = "{...};";` nor `rpc Foo (...) returns (...) { option ...; }`
/// can mis-close a service body.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Consume an identifier (alnum + `_` + `.` for dotted type names).
    /// Returns empty if the cursor isn't at an identifier start.
    fn read_ident(&mut self) -> String {
        self.skip_whitespace();
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()
    }

    fn expect(&mut self, ch: u8) {
        self.skip_whitespace();
        if self.peek() != Some(ch) {
            let lo = self.pos.saturating_sub(24);
            let hi = (self.pos + 24).min(self.bytes.len());
            panic!(
                "expected '{}' at byte {}, near: …{}…",
                ch as char,
                self.pos,
                String::from_utf8_lossy(&self.bytes[lo..hi]),
            );
        }
        self.pos += 1;
    }

    /// Walk past a string literal (cursor positioned AFTER the opening `"`).
    fn skip_string(&mut self) {
        while let Some(c) = self.bump() {
            match c {
                b'"' => return,
                b'\\' => {
                    self.bump();
                }
                _ => {}
            }
        }
    }

    /// Walk past a balanced `{ ... }` block (cursor positioned AFTER the opening `{`).
    fn skip_brace_block(&mut self) {
        let mut depth = 1;
        while depth > 0 {
            match self.bump() {
                Some(b'"') => self.skip_string(),
                Some(b'{') => depth += 1,
                Some(b'}') => depth -= 1,
                Some(_) => {}
                None => return,
            }
        }
    }

    /// Skip past the rest of a top-level statement — either `;` or a balanced
    /// `{ ... }` block. Used to discard non-`rpc` declarations inside service
    /// bodies and non-`service`/`package` declarations at file scope.
    fn skip_statement(&mut self) {
        loop {
            match self.bump() {
                Some(b';') => return,
                Some(b'{') => {
                    self.skip_brace_block();
                    return;
                }
                Some(b'"') => self.skip_string(),
                Some(b'}') | None => return,
                Some(_) => {}
            }
        }
    }
}

/// Strip `//` line comments and `/* … */` block comments. String literals are
/// passed through verbatim so a `"//"` or `"/*"` inside a string isn't elided.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        match (c, next) {
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                i += 2;
                while i + 1 < bytes.len() {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    if bytes[i] == b'\n' {
                        // Preserve newlines so panic-site context still lines up.
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            (b'"', _) => {
                out.push('"');
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        out.push(bytes[i] as char);
                        out.push(bytes[i + 1] as char);
                        i += 2;
                    } else {
                        out.push(bytes[i] as char);
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    out.push('"');
                    i += 1;
                }
            }
            _ => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

fn parse_proto_services(path: &Path) -> Vec<RpcService> {
    let raw = fs::read_to_string(path).expect("proto file should be readable");
    let source = strip_comments(&raw);
    let mut scanner = Scanner::new(&source);
    let mut package = String::new();
    let mut services = Vec::new();

    while !scanner.at_end() {
        scanner.skip_whitespace();
        if scanner.at_end() {
            break;
        }
        let keyword = scanner.read_ident();
        if keyword.is_empty() {
            // Stray punctuation at top level — discard one byte and retry.
            scanner.bump();
            continue;
        }
        match keyword.as_str() {
            "package" => {
                let pkg = scanner.read_ident();
                scanner.expect(b';');
                package = pkg;
            }
            "service" => {
                let name = scanner.read_ident();
                scanner.expect(b'{');
                let methods = parse_service_body(&mut scanner, &name);
                services.push(RpcService {
                    package: package.clone(),
                    name,
                    methods,
                });
            }
            _ => scanner.skip_statement(),
        }
    }

    services
}

fn parse_service_body(scanner: &mut Scanner<'_>, service_name: &str) -> Vec<RpcMethod> {
    let mut methods = Vec::new();
    loop {
        scanner.skip_whitespace();
        match scanner.peek() {
            Some(b'}') => {
                scanner.bump();
                return methods;
            }
            None => return methods,
            _ => {}
        }
        let keyword = scanner.read_ident();
        if keyword == "rpc" {
            methods.push(parse_rpc_method(scanner, service_name));
        } else {
            scanner.skip_statement();
        }
    }
}

fn parse_rpc_method(scanner: &mut Scanner<'_>, service_name: &str) -> RpcMethod {
    let name = scanner.read_ident();
    scanner.expect(b'(');
    let (request_stream, request) = parse_rpc_type(scanner);
    scanner.expect(b')');
    let returns = scanner.read_ident();
    assert_eq!(
        returns, "returns",
        "expected 'returns' after rpc request type in {service_name}.{name}",
    );
    scanner.expect(b'(');
    let (response_stream, response) = parse_rpc_type(scanner);
    scanner.expect(b')');
    scanner.skip_whitespace();
    // Trailing `;` or an optional method body `{ option … = …; … }`.
    match scanner.peek() {
        Some(b';') => {
            scanner.bump();
        }
        Some(b'{') => {
            scanner.bump();
            scanner.skip_brace_block();
        }
        _ => {}
    }
    RpcMethod {
        service: service_name.to_owned(),
        name,
        request,
        response,
        request_stream,
        response_stream,
    }
}

fn parse_rpc_type(scanner: &mut Scanner<'_>) -> (bool, String) {
    let first = scanner.read_ident();
    if first == "stream" {
        (true, scanner.read_ident())
    } else {
        (false, first)
    }
}

fn render_service_markers(services: &[RpcService]) -> String {
    let mut output = String::from(
        "// @generated by crates/rpc/build.rs. Do not edit by hand.\n\n\
         #[allow(unused_imports)]\n\
         use crate::peers::RpcService;\n\n",
    );

    for service in services {
        let service_ident = service_ident(&service.name);
        let service_name = format!("{}.{}", service.package, service.name);
        let alpn = format!("/{service_name}/1.0");
        let feature = feature_for_package(&service.package);
        output.push_str(&format!(
            "#[cfg(feature = \"{feature}\")]\n\
             pub struct {service_ident};\n\n\
             #[cfg(feature = \"{feature}\")]\n\
             impl RpcService for {service_ident} {{\n\
                 const NAME: &'static str = \"{service_name}\";\n\
                 const ALPN: &'static str = \"{alpn}\";\n\
             }}\n\n\
             #[cfg(feature = \"{feature}\")]\n\
             impl tonic::server::NamedService for {service_ident} {{\n\
                 const NAME: &'static str = <Self as RpcService>::NAME;\n\
             }}\n\n",
        ));
    }

    let method_counts = method_counts(services);
    output.push_str("pub mod methods {\n");
    output.push_str("    #[allow(unused_imports)]\n");
    output.push_str("    use crate::peers::RpcMethod;\n");
    for service in services {
        let feature = feature_for_package(&service.package);
        output.push_str(&format!(
            "    #[cfg(feature = \"{feature}\")]\n    use super::{};\n",
            service_ident(&service.name)
        ));
    }
    output.push('\n');

    for service in services {
        let service_ident = service_ident(&service.name);
        let feature = feature_for_package(&service.package);
        let service_name = format!("{}.{}", service.package, service.name);
        for method in &service.methods {
            let method_ident = method_ident(method, &method_counts);
            let request_ty = rust_type(&service.package, &method.request);
            let response_ty = rust_type(&service.package, &method.response);
            let grpc_path = format!("/{service_name}/{}", method.name);
            output.push_str(&format!(
                "    #[cfg(feature = \"{feature}\")]\n\
                 pub struct {method_ident};\n\n\
                 #[cfg(feature = \"{feature}\")]\n\
                 impl RpcMethod for {method_ident} {{\n\
                     type Service = {service_ident};\n\
                     type Request = {request_ty};\n\
                     type Response = {response_ty};\n\
                     const NAME: &'static str = \"{}\";\n\
                     const GRPC_PATH: &'static str = \"{grpc_path}\";\n\
                     const DEFAULT_COST: f32 = 1.0;\n\
                     const REQUEST_STREAMING: bool = {};\n\
                     const RESPONSE_STREAMING: bool = {};\n\
                 }}\n\n",
                method.name, method.request_stream, method.response_stream,
            ));
        }
    }

    output.push_str("}\n");
    output
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
