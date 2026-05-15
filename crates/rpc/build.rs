//! Build script for `hellas-rpc`.
//!
//! Pipeline:
//!
//! 1. Parse all `.proto` files at the workspace `proto/` root with `protox`
//!    (pure-Rust, no `protoc` dependency).
//! 2. Walk the resulting `FileDescriptorSet` to build an in-memory schema
//!    table and to derive per-method 32-bit IDs via
//!    `hellas_wire::MethodSchema::method_id()`.
//! 3. Hand the same `FileDescriptorSet` to `prost-build::Config::compile_fds`
//!    to emit the prost message types, and install a custom service
//!    generator (`HellasGenerator`) that emits typed service / method
//!    markers and client/server traits speaking the `hellas_wire` API.
//!
//! All output goes to `OUT_DIR`. The library `include!()`s the per-package
//! files from `src/pb/`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hellas_wire::schema::PrimKind;
use prost_build::{Method, Service, ServiceGenerator};
use prost_types::field_descriptor_proto::{Label, Type as FieldType};
use prost_types::{DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorSet};

fn main() {
    emit_git_rev();
    regenerate();
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

// =============================================================================
// Pipeline
// =============================================================================

fn regenerate() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let proto_root = manifest_dir.join("../../proto");
    let mut protos = Vec::new();
    collect_proto_files(&proto_root.join("hellas"), &mut protos);
    protos.sort();

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // 1. Parse with protox.
    let fds: FileDescriptorSet = protox::compile(&protos, &[&proto_root])
        .expect("protox failed to parse hellas .proto files");

    // 2. Build a schema table so we can resolve `.package.Name` references
    //    into `MessageSchema` (or `EnumRef`) and derive method IDs.
    let schema_index = SchemaIndex::build(&fds);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));

    // 3. Run prost-build with our custom generator. Generated message files
    //    land directly in OUT_DIR; per-package service-marker / trait code
    //    is emitted to OUT_DIR/hellas_rpc_services.rs by the generator.
    let services: Arc<Mutex<Vec<RpcService>>> = Arc::new(Mutex::new(Vec::new()));
    let generator = HellasGenerator {
        services: services.clone(),
    };

    let mut config = prost_build::Config::new();
    // NB: prost's `bytes(["."])` (decode `bytes` fields as `bytes::Bytes`
    // for zero-copy) is currently disabled because every consumer has
    // call sites that produce `Vec<u8>` and migrating them is a
    // separate, mechanical pass. See CUTOVER_FINDINGS.
    config.out_dir(&out_dir);
    config.service_generator(Box::new(generator));

    // prost-build needs a Clone-able copy because we also walked the same
    // FDS for schema indexing.
    config
        .compile_fds(fds.clone())
        .expect("prost-build failed to emit message types");

    // 4. Render and write the service / marker / client / server modules,
    //    keyed off the collected `RpcService` list and the schema index.
    let services_snapshot = services
        .lock()
        .expect("service collector mutex poisoned")
        .clone();

    let body = render_generated(&services_snapshot, &schema_index);
    let out_path = out_dir.join("hellas_rpc_services.rs");
    fs::write(&out_path, body).expect("failed to write hellas_rpc_services.rs");
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

// =============================================================================
// Service collection
// =============================================================================

/// Mirror of `prost_build::Service` decoupled from the generator lifetime so
/// the rendering code can run after `compile_fds` returns.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RpcService {
    /// `hellas.courtesy.v1`.
    package: String,
    /// `Courtesy`.
    proto_name: String,
    methods: Vec<RpcMethod>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RpcMethod {
    /// `QuotePrompt` (as it appears in the .proto).
    proto_name: String,
    /// Rust path of the request type (`super::QuotePromptRequest`, post-prost rewrites).
    request_rust_type: String,
    /// Rust path of the response type.
    response_rust_type: String,
    /// Fully-qualified proto request type, e.g. `.hellas.courtesy.v1.QuotePromptRequest`.
    request_proto_type: String,
    /// Fully-qualified proto response type, e.g. `.hellas.courtesy.v1.QuotePromptResponse`.
    response_proto_type: String,
    request_streaming: bool,
    response_streaming: bool,
}

struct HellasGenerator {
    services: Arc<Mutex<Vec<RpcService>>>,
}

impl ServiceGenerator for HellasGenerator {
    fn generate(&mut self, service: Service, _buf: &mut String) {
        let methods = service
            .methods
            .iter()
            .map(|m: &Method| RpcMethod {
                proto_name: m.proto_name.clone(),
                request_rust_type: m.input_type.clone(),
                response_rust_type: m.output_type.clone(),
                request_proto_type: ensure_dotted(&m.input_proto_type),
                response_proto_type: ensure_dotted(&m.output_proto_type),
                request_streaming: m.client_streaming,
                response_streaming: m.server_streaming,
            })
            .collect();
        self.services
            .lock()
            .expect("service vec poisoned")
            .push(RpcService {
                package: service.package.clone(),
                proto_name: service.proto_name.clone(),
                methods,
            });
    }
}

fn ensure_dotted(name: &str) -> String {
    if name.starts_with('.') {
        name.to_string()
    } else {
        format!(".{name}")
    }
}

// =============================================================================
// Schema index — walks the FileDescriptorSet to resolve message refs.
// =============================================================================

/// Owns the in-memory representation of every proto message and enum the
/// build script sees. The keys are fully-qualified names with a leading
/// dot (matching how prost reports `input_proto_type`).
struct SchemaIndex {
    messages: HashMap<String, IndexedMessage>,
    enums: HashMap<String, IndexedEnum>,
}

#[derive(Clone, Debug)]
struct IndexedMessage {
    /// Short proto name (`QuotePromptRequest`).
    short_name: String,
    fields: Vec<IndexedField>,
}

#[derive(Clone, Debug)]
struct IndexedField {
    number: u32,
    label: Label,
    ty: IndexedFieldType,
}

#[derive(Clone, Debug)]
enum IndexedFieldType {
    Primitive(PrimKind),
    Message(String), // FQN with leading dot
    Enum(String),    // FQN with leading dot
}

#[derive(Clone, Debug)]
struct IndexedEnum {
    short_name: String,
    variants: Vec<(String, i32)>,
}

impl SchemaIndex {
    fn build(fds: &FileDescriptorSet) -> Self {
        let mut messages = HashMap::new();
        let mut enums = HashMap::new();
        for file in &fds.file {
            let package = file.package.as_deref().unwrap_or("");
            for msg in &file.message_type {
                Self::index_message(package, "", msg, &mut messages, &mut enums);
            }
            for en in &file.enum_type {
                Self::index_enum(package, "", en, &mut enums);
            }
        }
        Self { messages, enums }
    }

    fn index_message(
        package: &str,
        parent_path: &str,
        msg: &DescriptorProto,
        messages: &mut HashMap<String, IndexedMessage>,
        enums: &mut HashMap<String, IndexedEnum>,
    ) {
        let short = msg.name.as_deref().unwrap_or_default();
        let fqn = compose_fqn(package, parent_path, short);
        let nested_path = if parent_path.is_empty() {
            short.to_string()
        } else {
            format!("{parent_path}.{short}")
        };
        let fields = msg
            .field
            .iter()
            .map(|f: &FieldDescriptorProto| IndexedField {
                number: f.number.unwrap_or_default() as u32,
                label: f
                    .label
                    .and_then(|v| Label::try_from(v).ok())
                    .unwrap_or(Label::Optional),
                ty: classify_field(f),
            })
            .collect();
        messages.insert(
            fqn.clone(),
            IndexedMessage {
                short_name: short.to_string(),
                fields,
            },
        );
        for nested in &msg.nested_type {
            Self::index_message(package, &nested_path, nested, messages, enums);
        }
        for nested_en in &msg.enum_type {
            Self::index_enum(package, &nested_path, nested_en, enums);
        }
    }

    fn index_enum(
        package: &str,
        parent_path: &str,
        en: &EnumDescriptorProto,
        enums: &mut HashMap<String, IndexedEnum>,
    ) {
        let short = en.name.as_deref().unwrap_or_default();
        let fqn = compose_fqn(package, parent_path, short);
        let variants = en
            .value
            .iter()
            .map(|v| {
                (
                    v.name.clone().unwrap_or_default(),
                    v.number.unwrap_or_default(),
                )
            })
            .collect();
        enums.insert(
            fqn,
            IndexedEnum {
                short_name: short.to_string(),
                variants,
            },
        );
    }

    /// Resolve a fully-qualified type reference (e.g. `.hellas.v1.Ticket`)
    /// into a `MessageSchema` recursively, owning all referenced strings.
    fn message_schema(&self, fqn: &str) -> OwnedMessageSchema {
        let msg = self
            .messages
            .get(fqn)
            .unwrap_or_else(|| panic!("missing message in schema index: {fqn}"));
        let mut visiting: Vec<String> = Vec::new();
        self.message_schema_inner(fqn, msg, &mut visiting)
    }

    fn message_schema_inner(
        &self,
        fqn: &str,
        msg: &IndexedMessage,
        visiting: &mut Vec<String>,
    ) -> OwnedMessageSchema {
        // Self-referential / mutually-recursive messages would diverge
        // here. We rely on the proto layer to keep service-facing trees
        // acyclic for now; emit a panic if violated so it surfaces
        // immediately rather than blowing the stack.
        if visiting.contains(&fqn.to_string()) {
            panic!("cyclic message schema at {fqn}; method-id derivation requires acyclic trees");
        }
        visiting.push(fqn.to_string());
        let fields = msg
            .fields
            .iter()
            .map(|f| OwnedFieldSchema {
                number: f.number,
                ty: self.field_schema(&f.ty, f.label, visiting),
            })
            .collect();
        visiting.pop();
        OwnedMessageSchema {
            name: msg.short_name.clone(),
            fields,
        }
    }

    fn field_schema(
        &self,
        ty: &IndexedFieldType,
        label: Label,
        visiting: &mut Vec<String>,
    ) -> OwnedTypeSchema {
        let base = match ty {
            IndexedFieldType::Primitive(p) => OwnedTypeSchema::Primitive(*p),
            IndexedFieldType::Message(fqn) => {
                let msg = self
                    .messages
                    .get(fqn)
                    .unwrap_or_else(|| panic!("missing message in schema index: {fqn}"));
                OwnedTypeSchema::Message(self.message_schema_inner(fqn, msg, visiting))
            }
            IndexedFieldType::Enum(fqn) => {
                let en = self
                    .enums
                    .get(fqn)
                    .unwrap_or_else(|| panic!("missing enum in schema index: {fqn}"));
                OwnedTypeSchema::EnumRef {
                    name: en.short_name.clone(),
                    variants: en.variants.clone(),
                }
            }
        };
        match label {
            Label::Repeated => OwnedTypeSchema::Repeated(Box::new(base)),
            _ => base,
        }
    }
}

fn compose_fqn(package: &str, parent_path: &str, short: &str) -> String {
    let mut out = String::with_capacity(package.len() + parent_path.len() + short.len() + 3);
    out.push('.');
    if !package.is_empty() {
        out.push_str(package);
        out.push('.');
    }
    if !parent_path.is_empty() {
        out.push_str(parent_path);
        out.push('.');
    }
    out.push_str(short);
    out
}

fn classify_field(f: &FieldDescriptorProto) -> IndexedFieldType {
    let ty = f
        .r#type
        .and_then(|v| FieldType::try_from(v).ok())
        .expect("field has a type");
    match ty {
        FieldType::Double => IndexedFieldType::Primitive(PrimKind::Double),
        FieldType::Float => IndexedFieldType::Primitive(PrimKind::Float),
        FieldType::Int64 => IndexedFieldType::Primitive(PrimKind::I64),
        FieldType::Uint64 => IndexedFieldType::Primitive(PrimKind::U64),
        FieldType::Int32 => IndexedFieldType::Primitive(PrimKind::I32),
        FieldType::Fixed64 => IndexedFieldType::Primitive(PrimKind::Fixed64),
        FieldType::Fixed32 => IndexedFieldType::Primitive(PrimKind::Fixed32),
        FieldType::Bool => IndexedFieldType::Primitive(PrimKind::Bool),
        FieldType::String => IndexedFieldType::Primitive(PrimKind::String),
        FieldType::Bytes => IndexedFieldType::Primitive(PrimKind::Bytes),
        FieldType::Uint32 => IndexedFieldType::Primitive(PrimKind::U32),
        FieldType::Sfixed32 => IndexedFieldType::Primitive(PrimKind::Sfixed32),
        FieldType::Sfixed64 => IndexedFieldType::Primitive(PrimKind::Sfixed64),
        FieldType::Sint32 => IndexedFieldType::Primitive(PrimKind::Sint32),
        FieldType::Sint64 => IndexedFieldType::Primitive(PrimKind::Sint64),
        FieldType::Enum => IndexedFieldType::Enum(
            f.type_name
                .clone()
                .expect("enum field carries a type_name"),
        ),
        FieldType::Message | FieldType::Group => IndexedFieldType::Message(
            f.type_name
                .clone()
                .expect("message field carries a type_name"),
        ),
    }
}

// =============================================================================
// Owned schema mirror (heap-backed; `MethodSchema<'a>` only borrows from
// these for the duration of the digest computation).
// =============================================================================

struct OwnedMethodSchema {
    fqn: String,
    request: OwnedTypeSchema,
    response: OwnedTypeSchema,
    request_streaming: bool,
    response_streaming: bool,
}

#[derive(Clone)]
struct OwnedMessageSchema {
    name: String,
    fields: Vec<OwnedFieldSchema>,
}

#[derive(Clone)]
struct OwnedFieldSchema {
    number: u32,
    ty: OwnedTypeSchema,
}

#[derive(Clone)]
enum OwnedTypeSchema {
    Primitive(PrimKind),
    Message(OwnedMessageSchema),
    EnumRef {
        name: String,
        variants: Vec<(String, i32)>,
    },
    Repeated(Box<OwnedTypeSchema>),
}

impl OwnedMethodSchema {
    fn method_id(&self) -> u32 {
        // Encode directly to a blake3::Hasher in the same byte order as
        // `hellas_wire::schema::MethodSchema::encode_to`. Sidesteps the
        // self-referential lifetime gymnastics of building borrowed
        // `MethodSchema<'a>` values.
        let mut hasher = blake3::Hasher::new();
        hasher.update(hellas_wire::schema::METHOD_DOMAIN);
        encode_str(&self.fqn, &mut hasher);
        encode_owned_type(&self.request, &mut hasher);
        encode_owned_type(&self.response, &mut hasher);
        hasher.update(&[u8::from(self.request_streaming)]);
        hasher.update(&[u8::from(self.response_streaming)]);
        let d = *hasher.finalize().as_bytes();
        u32::from_le_bytes([d[0], d[1], d[2], d[3]])
    }
}

fn encode_str(s: &str, hasher: &mut blake3::Hasher) {
    let len = u32::try_from(s.len()).expect("str length fits u32");
    hasher.update(&len.to_be_bytes());
    hasher.update(s.as_bytes());
}

fn encode_owned_type(ty: &OwnedTypeSchema, hasher: &mut blake3::Hasher) {
    match ty {
        OwnedTypeSchema::Primitive(p) => {
            hasher.update(&[0]);
            hasher.update(&[*p as u8]);
        }
        OwnedTypeSchema::Message(msg) => {
            hasher.update(&[1]);
            encode_str(&msg.name, hasher);
            let len = u32::try_from(msg.fields.len()).expect("fields fit u32");
            hasher.update(&len.to_be_bytes());
            for f in &msg.fields {
                hasher.update(&f.number.to_be_bytes());
                encode_owned_type(&f.ty, hasher);
            }
        }
        OwnedTypeSchema::EnumRef { name, variants } => {
            hasher.update(&[2]);
            encode_str(name, hasher);
            let len = u32::try_from(variants.len()).expect("variants fit u32");
            hasher.update(&len.to_be_bytes());
            for (n, v) in variants {
                encode_str(n, hasher);
                hasher.update(&v.to_be_bytes());
            }
        }
        OwnedTypeSchema::Repeated(inner) => {
            hasher.update(&[3]);
            encode_owned_type(inner, hasher);
        }
    }
}

// =============================================================================
// Code generation
// =============================================================================

fn render_generated(services: &[RpcService], index: &SchemaIndex) -> String {
    let mut out = String::new();
    out.push_str(
        "// @generated by `hellas-rpc` build.rs. Do not edit by hand.\n\
         //\n\
         // Service / method markers, typed client traits, and server\n\
         // dispatcher stubs. The wrapping module sets allow-lints.\n\n",
    );

    // The generated file is included from `src/pb/services.rs`. Every type
    // reference is rooted at the corresponding `crate::pb::<package>` module
    // (see `package_rust_path`). The pb modules in turn `include!()` the
    // prost-generated `<package>.rs` files from OUT_DIR.

    // Inventory: every service and every rate-limited method, regardless of
    // feature gating. Transport-layer code iterates these without
    // re-declaring service names.
    out.push_str("/// A protocol-level service entry — its FQN and the wire ALPN.\n");
    out.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n");
    out.push_str("pub struct KnownService {\n    pub name: &'static str,\n    pub alpn: &'static str,\n}\n\n");

    out.push_str("/// Catalogue of every service this crate knows about.\n");
    out.push_str("pub const KNOWN_SERVICES: &[KnownService] = &[\n");
    for service in services {
        let fqn = format!("{}.{}", service.package, service.proto_name);
        let alpn = format!("/{fqn}/1.0");
        out.push_str(&format!(
            "    KnownService {{ name: {:?}, alpn: {:?} }},\n",
            fqn, alpn
        ));
    }
    out.push_str("];\n\n");

    // Method ID table (string → u32). Used by inbound dispatch to
    // translate legacy gRPC paths during the migration. Kept independently
    // of the cfg-gated marker impls so callers always see the full table.
    out.push_str("/// All method IDs known at codegen time, keyed by `service_fqn/method_name`.\n");
    out.push_str("pub const KNOWN_METHOD_IDS: &[(&'static str, u32)] = &[\n");
    for service in services {
        let fqn = format!("{}.{}", service.package, service.proto_name);
        for method in &service.methods {
            let method_fqn = format!("{fqn}.{}", method.proto_name);
            let owned = build_method_schema(&fqn, method, index);
            let id = owned.method_id();
            out.push_str(&format!(
                "    ({:?}, 0x{:08x}),\n",
                format!("/{fqn}/{}", method.proto_name),
                id
            ));
            // Suppress unused-variable warning for symmetry.
            let _ = method_fqn;
        }
    }
    out.push_str("];\n\n");

    for service in services {
        render_service_block(&mut out, service, index);
    }

    out
}

fn render_service_block(out: &mut String, service: &RpcService, index: &SchemaIndex) {
    let feature = feature_for_package(&service.package);
    let fqn = format!("{}.{}", service.package, service.proto_name);
    let alpn = format!("/{fqn}/1.0");
    let module_name = service_module_ident(&service.proto_name);

    // Service ID (low-32 of blake3 of canonicalized ServiceSchema).
    let service_id = compute_service_id(&fqn, service, index);

    out.push_str(&format!(
        "#[cfg(feature = \"{feature}\")]\npub mod {module_name} {{\n"
    ));
    out.push_str("    use ::hellas_wire::{MethodMarker, ServiceMarker};\n\n");

    // -- Service marker --
    out.push_str(&format!("    pub struct {};\n\n", service.proto_name));
    out.push_str(&format!(
        "    impl ServiceMarker for {} {{\n\
        \x20       const NAME: &'static str = {:?};\n\
        \x20       const ALPN: &'static str = {:?};\n\
        \x20       const SERVICE_ID: u32 = 0x{:08x};\n\
        \x20   }}\n\n",
        service.proto_name, fqn, alpn, service_id
    ));

    // -- Method markers --
    for method in &service.methods {
        let method_name = &method.proto_name;
        let owned = build_method_schema(&fqn, method, index);
        let method_id = owned.method_id();
        let request_ty = proto_fqn_to_rust_path(&method.request_proto_type);
        let response_ty = proto_fqn_to_rust_path(&method.response_proto_type);
        out.push_str(&format!("    pub struct {method_name};\n\n"));
        out.push_str(&format!(
            "    impl MethodMarker for {method_name} {{\n\
            \x20       type Service = {service};\n\
            \x20       type Request = {request_ty};\n\
            \x20       type Response = {response_ty};\n\
            \x20       const NAME: &'static str = {name:?};\n\
            \x20       const METHOD_ID: u32 = 0x{id:08x};\n\
            \x20       const REQUEST_STREAMING: bool = {req_stream};\n\
            \x20       const RESPONSE_STREAMING: bool = {resp_stream};\n\
            \x20   }}\n\n",
            service = service.proto_name,
            request_ty = request_ty,
            response_ty = response_ty,
            name = method_name,
            id = method_id,
            req_stream = method.request_streaming,
            resp_stream = method.response_streaming,
        ));
    }

    // -- Client trait --
    let client_trait = format!("{}Client", service.proto_name);
    out.push_str(&format!(
        "    /// Typed client trait — one method per RPC. Wraps the\n\
        \x20   /// underlying `StreamTransport` with prost encode/decode.\n\
        \x20   ///\n\
        \x20   /// TODO(hellas-wire v2): the method bodies currently `unimplemented!()`\n\
        \x20   /// — the consumer migration phase fills them in.\n\
        \x20   pub trait {client_trait}<T: ::hellas_wire::StreamTransport> {{\n",
        client_trait = client_trait,
    ));
    for method in &service.methods {
        let fn_name = to_snake_case(&method.proto_name);
        let request_ty = proto_fqn_to_rust_path(&method.request_proto_type);
        let response_ty = proto_fqn_to_rust_path(&method.response_proto_type);
        let (sig_req, sig_resp) = client_signature(method, &request_ty, &response_ty);
        out.push_str(&format!(
            "        fn {fn_name}(&self, request: {sig_req}) -> impl ::core::future::Future<Output = ::core::result::Result<{sig_resp}, ::hellas_wire::WireStatus>> + Send;\n",
        ));
    }
    out.push_str("    }\n\n");

    // -- Server trait --
    let server_trait = format!("{}Handler", service.proto_name);
    out.push_str(&format!(
        "    /// Server-side handler trait. Concrete servers implement\n\
        \x20   /// this; the generated `{server}Server` dispatcher routes inbound\n\
        \x20   /// frames to the matching handler.\n\
        \x20   pub trait {server_trait}: Send + Sync + 'static {{\n",
        server = service.proto_name,
        server_trait = server_trait,
    ));
    for method in &service.methods {
        let fn_name = to_snake_case(&method.proto_name);
        let request_ty = proto_fqn_to_rust_path(&method.request_proto_type);
        let response_ty = proto_fqn_to_rust_path(&method.response_proto_type);
        let (sig_req, sig_resp) = server_signature(method, &request_ty, &response_ty);
        // For unary methods, allow the handler to return either the bare
        // response type or `WithTrailer<R>` (which carries response-side
        // metadata like provenance). For streaming methods, keep the
        // stream-type return as-is.
        let handler_resp = if !method.request_streaming && !method.response_streaming {
            format!("impl Into<crate::call::WithTrailer<{sig_resp}>> + Send", sig_resp = sig_resp)
        } else {
            sig_resp.clone()
        };
        out.push_str(&format!(
            "        fn {fn_name}(&self, request: {sig_req}) -> impl ::core::future::Future<Output = ::core::result::Result<{handler_resp}, ::hellas_wire::WireStatus>> + Send;\n",
        ));
    }
    out.push_str("    }\n\n");

    // -- Generic Client impl over any StreamTransport, using rpc::call helpers --
    let client_impl_name = format!("{}ClientImpl", service.proto_name);
    out.push_str(&format!(
        "    /// Generic client over any `StreamTransport`. Wraps a transport\n\
        \x20   /// handle by reference; clone to share. Uses the prost-aware\n\
        \x20   /// helpers in `crate::call`.\n\
        \x20   #[derive(Clone, Debug)]\n\
        \x20   pub struct {client_impl_name}<T> {{\n\
        \x20       transport: T,\n\
        \x20   }}\n\n\
        \x20   impl<T> {client_impl_name}<T> {{\n\
        \x20       pub fn new(transport: T) -> Self {{\n\
        \x20           Self {{ transport }}\n\
        \x20       }}\n\
        \x20   }}\n\n",
        client_impl_name = client_impl_name,
    ));
    // Client trait impl bodies that delegate to the call helpers.
    out.push_str(&format!(
        "    impl<T> {client_trait}<T> for {client_impl_name}<T>\n\
        \x20   where\n\
        \x20       T: ::hellas_wire::StreamTransport + Sync,\n\
        \x20       T::Error: ::std::error::Error + Send + Sync + 'static,\n\
        \x20       T::Stream: 'static,\n\
        \x20   {{\n",
        client_trait = client_trait,
        client_impl_name = client_impl_name,
    ));
    for method in &service.methods {
        let fn_name = to_snake_case(&method.proto_name);
        let request_ty = proto_fqn_to_rust_path(&method.request_proto_type);
        let response_ty = proto_fqn_to_rust_path(&method.response_proto_type);
        let (sig_req, sig_resp) = client_signature(method, &request_ty, &response_ty);
        let method_marker = &method.proto_name;
        // For now, only unary and server-streaming have real impls; others stub.
        let body = match (method.request_streaming, method.response_streaming) {
            (false, false) => format!(
                "            async move {{\n\
                \x20               crate::call::unary::<T, {method_marker}>(\n\
                \x20                   &self.transport, request, ::hellas_wire::Metadata::new()).await\n\
                \x20           }}",
                method_marker = method_marker,
            ),
            (false, true) => "            async move { unimplemented!(\"adapter built below\") }".to_string(),
            _ => "            async move { unimplemented!(\"client/bidi streaming pending\") }".to_string(),
        };
        // Pure server-streaming (unary request, streaming response) gets a
        // real impl via `crate::call::server_streaming`. All other streaming
        // shapes (client-stream, bidi) stay stubbed pending more helpers.
        let (real_sig_resp, body) = if method.response_streaming && !method.request_streaming {
            (
                format!(
                    "crate::call::StreamingCall<{resp}>",
                    resp = response_ty
                ),
                format!(
                    "            async move {{\n\
                    \x20               crate::call::server_streaming::<T, {method_marker}>(\n\
                    \x20                   &self.transport, request, ::hellas_wire::Metadata::new()).await\n\
                    \x20           }}",
                    method_marker = method_marker,
                ),
            )
        } else if method.response_streaming {
            // client-stream/bidi: keep the same response type as pure server-streaming
            // (`StreamingCall<R>`) but stub the body until the wire-v2 helpers land.
            (
                format!(
                    "crate::call::StreamingCall<{resp}>",
                    resp = response_ty
                ),
                "            async move { let _ = request; unimplemented!(\"client/bidi streaming pending\") }".to_string(),
            )
        } else {
            (sig_resp.clone(), body)
        };
        out.push_str(&format!(
            "        fn {fn_name}(&self, request: {sig_req}) -> impl ::core::future::Future<Output = ::core::result::Result<{real_sig_resp}, ::hellas_wire::WireStatus>> + Send {{\n\
            {body}\n\
            \x20       }}\n",
        ));
    }
    out.push_str("    }\n\n");

    // -- Server dispatcher --
    out.push_str(&format!(
        "    /// Wraps a `{server_trait}` and routes inbound streams to it\n\
        \x20   /// by `method_id`. For unary methods the dispatch decodes the\n\
        \x20   /// request, invokes the handler, encodes the response, and\n\
        \x20   /// emits a terminal trailer. Streaming methods are stubbed\n\
        \x20   /// pending wire-v2 ergonomics.\n\
        \x20   pub struct {service}Server<H>(pub H);\n\n\
        \x20   impl<T, H> ::hellas_wire::Dispatcher<T> for {service}Server<H>\n\
        \x20   where\n\
        \x20       T: ::hellas_wire::StreamTransport + Send + Sync,\n\
        \x20       H: {server_trait},\n\
        \x20   {{\n\
        \x20       type Error = ::hellas_wire::TransportError;\n\n\
        \x20       async fn dispatch(\n\
        \x20           &self,\n\
        \x20           inbound: ::hellas_wire::Inbound<T::Stream>,\n\
        \x20       ) -> ::core::result::Result<(), Self::Error> {{\n\
        \x20           match inbound.method_id {{\n",
        service = service.proto_name,
        server_trait = server_trait,
    ));
    for method in &service.methods {
        let fn_name = to_snake_case(&method.proto_name);
        let method_marker = &method.proto_name;
        let case_body = match (method.request_streaming, method.response_streaming) {
            (false, false) => format!(
                "                <{method_marker} as ::hellas_wire::MethodMarker>::METHOD_ID => {{\n\
                \x20                   crate::call::dispatch_unary::<T, {method_marker}, _, _, _>(inbound, |req| {{\n\
                \x20                       let h = &self.0;\n\
                \x20                       async move {{ h.{fn_name}(req).await }}\n\
                \x20                   }}).await\n\
                \x20               }}",
                method_marker = method_marker,
                fn_name = fn_name,
            ),
            (false, true) => format!(
                "                <{method_marker} as ::hellas_wire::MethodMarker>::METHOD_ID => {{\n\
                \x20                   crate::call::dispatch_server_streaming::<T, {method_marker}, _, _, _>(inbound, |req| {{\n\
                \x20                       let h = &self.0;\n\
                \x20                       async move {{ h.{fn_name}(req).await }}\n\
                \x20                   }}).await\n\
                \x20               }}",
                method_marker = method_marker,
                fn_name = fn_name,
            ),
            _ => format!(
                "                <{method_marker} as ::hellas_wire::MethodMarker>::METHOD_ID => {{\n\
                \x20                   let _ = (&self.0, inbound);\n\
                \x20                   ::core::result::Result::Err(::hellas_wire::TransportError::Protocol(\n\
                \x20                       \"client/bidi streaming dispatch pending for {method_marker}\".to_string()\n\
                \x20                   ))\n\
                \x20               }}",
                method_marker = method_marker,
            ),
        };
        out.push_str(&case_body);
        out.push('\n');
    }
    out.push_str(
        "                other => Err(::hellas_wire::TransportError::Protocol(\n\
        \x20                   format!(\"unknown method_id 0x{:08x}\", other)\n\
        \x20               )),\n\
        \x20           }\n\
        \x20       }\n\
        \x20   }\n\n",
    );

    out.push_str("}\n\n");
}

fn build_method_schema(
    service_fqn: &str,
    method: &RpcMethod,
    index: &SchemaIndex,
) -> OwnedMethodSchema {
    let request_msg = index.message_schema(&method.request_proto_type);
    let response_msg = index.message_schema(&method.response_proto_type);
    OwnedMethodSchema {
        // FQN matches HELLAS_WIRE_PLAN_v2.md's "Service/Method"
        // convention — same shape as the gRPC :path on h2/h3.
        fqn: format!("{service_fqn}/{}", method.proto_name),
        request: OwnedTypeSchema::Message(request_msg),
        response: OwnedTypeSchema::Message(response_msg),
        request_streaming: method.request_streaming,
        response_streaming: method.response_streaming,
    }
}

fn compute_service_id(fqn: &str, service: &RpcService, index: &SchemaIndex) -> u32 {
    let methods: Vec<OwnedMethodSchema> = service
        .methods
        .iter()
        .map(|m| build_method_schema(fqn, m, index))
        .collect();

    // Encode the ServiceSchema canonical form directly to a blake3
    // hasher, mirroring `hellas_wire::schema::ServiceSchema::encode_to`.
    let mut hasher = blake3::Hasher::new();
    hasher.update(hellas_wire::schema::SERVICE_DOMAIN);
    encode_str(fqn, &mut hasher);
    let len = u32::try_from(methods.len()).expect("methods fit u32");
    hasher.update(&len.to_be_bytes());
    for m in &methods {
        encode_str(&m.fqn, &mut hasher);
        encode_owned_type(&m.request, &mut hasher);
        encode_owned_type(&m.response, &mut hasher);
        hasher.update(&[u8::from(m.request_streaming)]);
        hasher.update(&[u8::from(m.response_streaming)]);
    }
    let d = *hasher.finalize().as_bytes();
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

fn client_signature(method: &RpcMethod, req: &str, resp: &str) -> (String, String) {
    let req_sig = if method.request_streaming {
        format!("impl ::futures_core::Stream<Item = {req}> + Send + Unpin")
    } else {
        req.to_string()
    };
    let resp_sig = if method.response_streaming {
        format!("crate::call::StreamingCall<{resp}>")
    } else {
        resp.to_string()
    };
    (req_sig, resp_sig)
}

fn server_signature(method: &RpcMethod, req: &str, resp: &str) -> (String, String) {
    let req_sig = if method.request_streaming {
        format!("::std::pin::Pin<Box<dyn ::futures_core::Stream<Item = {req}> + Send>>")
    } else {
        req.to_string()
    };
    let resp_sig = if method.response_streaming {
        format!("::std::pin::Pin<Box<dyn ::futures_core::Stream<Item = ::core::result::Result<{resp}, ::hellas_wire::WireStatus>> + Send>>")
    } else {
        resp.to_string()
    };
    (req_sig, resp_sig)
}

fn service_module_ident(proto_name: &str) -> String {
    to_snake_case(proto_name)
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

/// Translate a fully-qualified proto type (e.g. `.hellas.swarm.v1.GetNodeInfoResponse`)
/// into an absolute Rust path under `crate::pb::hellas::...`. Prost's
/// `input_type` field is *relative* to the per-package module it generated,
/// so it isn't usable from the centralized `pb::services` module without
/// rewriting.
///
/// Nested message types (`.pkg.Parent.Child`) come through as Parent.child
/// in proto naming — translated as `parent::Child` in Rust by prost's own
/// scheme. We don't currently have nested message types in any hellas
/// .proto, so a flat translation is enough; if that ever changes, extend
/// the lowercase rule below.
fn proto_fqn_to_rust_path(proto_fqn: &str) -> String {
    // Strip leading dot.
    let stripped = proto_fqn.strip_prefix('.').unwrap_or(proto_fqn);
    // Split into segments. The last segment is the type name (PascalCase);
    // every preceding segment is a module (snake_case in the .proto, which
    // already lowercase).
    let mut segments: Vec<&str> = stripped.split('.').collect();
    let type_name = segments
        .pop()
        .expect("proto fqn has at least one segment");
    let mut path = String::from("crate::pb");
    for seg in segments {
        path.push_str("::");
        path.push_str(seg);
    }
    path.push_str("::");
    path.push_str(type_name);
    path
}
