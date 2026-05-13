use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote};

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
    let client_traits = render_client_traits(&services);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out_dir.join("service_markers.rs"), service_markers)
        .expect("failed to write generated service markers");
    fs::write(out_dir.join("client_traits.rs"), client_traits)
        .expect("failed to write generated client traits");
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
    let method_counts = method_counts(services);

    let service_marker_impls = services.iter().map(|service| {
        let service_ident = format_ident!("{}Service", service.name);
        let service_name = format!("{}.{}", service.package, service.name);
        let alpn = format!("/{service_name}/1.0");
        let feature = feature_for_package(&service.package);
        quote! {
            #[cfg(feature = #feature)]
            pub struct #service_ident;

            #[cfg(feature = #feature)]
            impl RpcService for #service_ident {
                const NAME: &'static str = #service_name;
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
                syn::parse_str(&rust_type(&service.package, &method.request))
                    .expect("request type parses as Rust");
            let response_ty: syn::Type =
                syn::parse_str(&rust_type(&service.package, &method.response))
                    .expect("response type parses as Rust");
            let method_name = &method.name;
            let grpc_path = format!("/{service_name}/{method_name}");
            let request_streaming = method.request_stream;
            let response_streaming = method.response_stream;
            method_marker_impls.push(quote! {
                #[cfg(feature = #feature)]
                pub struct #method_ident_tok;

                #[cfg(feature = #feature)]
                impl RpcMethod for #method_ident_tok {
                    type Service = #service_ident;
                    type Request = #request_ty;
                    type Response = #response_ty;
                    const NAME: &'static str = #method_name;
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
            let constructor = if is_rate_limited(&service.package, &service.name, &method.name) {
                format_ident!("rate_limited_method")
            } else {
                format_ident!("account_method")
            };
            arms.push(quote! {
                <methods::#method_ident_tok as crate::peers::RpcMethod>::GRPC_PATH
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

    let tokens = quote! {
        #[allow(unused_imports)]
        use crate::peers::RpcService;

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
/// Pre-refactor `node.rs` rate-limited `swarm.v1.Node/GetKnownPeers` via
/// `InboundRequestPolicy::rate_limited_method`. The codegen-emitted
/// `RpcServiceSpec` must preserve that or the `ManagedServer` denial path
/// becomes unreachable in production.
///
/// Add other entries here, or move the table to a `.proto` annotation once
/// the parser learns to read `option (hellas.inbound) = …`.
fn is_rate_limited(package: &str, service: &str, method: &str) -> bool {
    matches!(
        (package, service, method),
        ("hellas.swarm.v1", "Node", "GetKnownPeers")
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
///
/// Each emitted trait method picks the correct `crate::call::*Call<M>` type
/// based on streaming flags so user code writes the typed style:
///
/// ```ignore
/// use hellas_rpc::client::CourtesyClient;
/// let resp = transport.peer(id).list_models(req).await?;
/// ```
fn render_client_traits(services: &[RpcService]) -> String {
    let method_counts = method_counts(services);

    let service_blocks = services.iter().map(|service| {
        let trait_name = format_ident!("{}Client", service.name);
        let feature = feature_for_package(&service.package);

        let trait_methods = service
            .methods
            .iter()
            .map(|method| client_trait_method(service, method, &method_counts));
        let impl_methods = service
            .methods
            .iter()
            .map(|method| client_impl_method(service, method, &method_counts));

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
    service: &RpcService,
    method: &RpcMethod,
    method_counts: &HashMap<String, usize>,
) -> TokenStream {
    let fn_name = format_ident!("{}", to_snake_case(&method.name));
    let request_arg = client_request_arg(service, method);
    let call_ty = call_type_for(method, method_counts);
    quote! {
        fn #fn_name(&self, request: #request_arg) -> #call_ty;
    }
}

fn client_impl_method(
    service: &RpcService,
    method: &RpcMethod,
    method_counts: &HashMap<String, usize>,
) -> TokenStream {
    let fn_name = format_ident!("{}", to_snake_case(&method.name));
    let request_arg = client_request_arg(service, method);
    let call_ty = call_type_for(method, method_counts);
    let call_prefix = format_ident!("{}", call_prefix(method));
    let marker_ident = format_ident!("{}", method_ident(method, method_counts));
    quote! {
        fn #fn_name(&self, request: #request_arg) -> #call_ty {
            crate::call::#call_prefix::<crate::service::methods::#marker_ident>::new(self.clone(), request)
        }
    }
}

/// Build the `request:` parameter type for a generated trait/impl method.
/// Servers expose tonic-style "IntoRequest" or "IntoStreamingRequest" so call
/// sites can pass raw messages or `tonic::Request<T>` interchangeably.
fn client_request_arg(service: &RpcService, method: &RpcMethod) -> TokenStream {
    let request_ty: syn::Type = syn::parse_str(&rust_type(&service.package, &method.request))
        .expect("request type parses as Rust");
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

/// Format a `TokenStream` back into idiomatic Rust source via prettyplease.
/// Errors only fire when the tokens are syntactically invalid — that's a bug
/// in this build script, not user input, so unwrap is appropriate.
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
    format!("// @generated by crates/rpc/build.rs. Do not edit by hand.\n\n{body}")
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

/// Map a protobuf package name to the `hellas_pb` submodule that hosts its
/// generated types. The convention is "last namespace component, skipping a
/// trailing `vN` version segment":
///
///   hellas.v1               -> hellas
///   hellas.swarm.v1         -> swarm
///   hellas.courtesy.v1      -> courtesy
///   hellas.opaque.v1        -> opaque
///   hellas.symbolic.v1      -> symbolic
///
/// New packages that follow the same pattern slot in without a code change.
fn pb_module_for_package(package: &str) -> String {
    let mut parts: Vec<&str> = package.split('.').collect();
    if let Some(last) = parts.last()
        && last.starts_with('v')
        && last[1..].bytes().all(|b| b.is_ascii_digit())
        && parts.len() > 1
    {
        parts.pop();
    }
    parts
        .last()
        .copied()
        .unwrap_or(package)
        .to_string()
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
