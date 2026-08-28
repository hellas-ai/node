//! The two things that stand between an HTTP caller and the executor: a
//! per-run bearer credential, and a bind address that is loopback by
//! parse rather than by spelling.
//!
//! The gateway's routes reach an `ExecutorHandle`. Before this module
//! they were reachable by anyone who could open the port, which made the
//! bind address the entire access control. Now every executor-reaching
//! route — and, when it is switched on, the metrics endpoint — sits
//! behind [`BearerLayer`], and the listener refuses to come up anywhere
//! but loopback.
//!
//! The credential lives for one run. It is generated at startup, kept in
//! memory, shown once on the controlling terminal, and never written
//! anywhere else: [`Bearer`]'s `Debug` is redacted so it cannot reach a
//! log through a `{:?}` on a struct that happens to contain it, and the
//! refusal response names no value it was given.

use axum::body::Body;
use axum::http::{HeaderMap, Request, Response, StatusCode, header};
use futures::future::BoxFuture;
use hellas_rpc::provenance::encode_hex;
use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// 256 bits, per §8. Rendered to the operator as lowercase hex, so the
/// credential is `TOKEN_HEX_LEN` characters on the wire.
const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// A value no hex nibble can take, returned for any byte that is not a
/// lowercase hex digit. A sentinel rather than an `Option` keeps
/// [`Bearer::accepts`]'s loop straight-line.
const NOT_A_DIGIT: usize = 0x100;

/// Digit steps taken by [`Bearer::accepts`], so tests can assert the work
/// is the same for every input length instead of timing it.
#[cfg(test)]
static DIGIT_STEPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The run's bearer credential.
///
/// There is no `Display`, no `Serialize`, and no derived `Debug`: the
/// only way out of this type is [`Bearer::announce`], which writes to the
/// terminal and to nothing else.
pub(crate) struct Bearer {
    token: [u8; TOKEN_BYTES],
}

impl Bearer {
    /// Draw a fresh credential for this run. Not configured and not
    /// persisted: a restart invalidates the old one, which is the point.
    pub(crate) fn generate() -> Self {
        Self {
            token: rand::random(),
        }
    }

    /// Show the operator the credential exactly once, on the controlling
    /// terminal.
    ///
    /// `/dev/tty` is the terminal this process is attached to. It is
    /// neither stdout nor stderr, so nothing that captures those sees it:
    /// not a `>` redirect, not a pipe into a log shipper, not systemd's
    /// `StandardOutput=journal`. Where there is no controlling terminal —
    /// a systemd unit, a container started without a tty — the open fails
    /// and we print nothing rather than fall back to a stream that is
    /// captured by construction. The operator is told that happened; the
    /// credential itself stays in memory.
    pub(crate) fn announce(&self) {
        let line = format!(
            "gateway bearer (this run only): Authorization: Bearer {}\n",
            encode_hex(&self.token)
        );
        match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            Ok(mut tty) => {
                if let Err(err) = tty.write_all(line.as_bytes()) {
                    info!("gateway bearer not shown: writing to /dev/tty failed: {err}");
                }
            }
            Err(err) => {
                info!("gateway bearer not shown: no controlling terminal ({err})");
            }
        }
    }

    /// The credential as a child process we spawn must present it.
    ///
    /// The one way out of this type other than [`Bearer::announce`], and
    /// it exists for `--wrap`: a command the gateway starts itself, on
    /// this machine, whose requests would otherwise all be refused. It
    /// goes into that child's environment and nowhere else — never into
    /// a log line, an error, or a header we emit.
    pub(crate) fn child_credential(&self) -> String {
        encode_hex(&self.token)
    }

    /// Whether `headers` carries this run's credential in
    /// `Authorization: Bearer …`.
    ///
    /// Only that header is consulted. A query parameter never reaches
    /// here, and neither does any other header name, however well the
    /// value matches.
    fn authorizes(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get(header::AUTHORIZATION) else {
            return false;
        };
        let Some(credential) = strip_bearer(value.as_bytes()) else {
            return false;
        };
        self.accepts(credential)
    }

    /// Whether `presented` is this run's credential.
    ///
    /// The work is fixed at `TOKEN_HEX_LEN` digit steps for every input,
    /// whatever its length: a short credential, a long one, and a
    /// right-length wrong one all cost the same. The length disagreement
    /// is folded into the accumulator instead of being returned on —
    /// an `if presented.len() != TOKEN_HEX_LEN { return false }` here is
    /// exactly the short-circuit §8 forbids, because it answers "how long
    /// is the secret" before it answers anything else.
    ///
    /// [`hex_digit`] does branch, but only on a byte the caller chose and
    /// already knows; nothing in this loop branches on `self.token`.
    fn accepts(&self, presented: &[u8]) -> bool {
        let mut diff = presented.len() ^ TOKEN_HEX_LEN;
        for index in 0..TOKEN_HEX_LEN {
            #[cfg(test)]
            DIGIT_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Past the end of a short credential we decode a fixed
            // filler, so the step count never depends on the length.
            let digit = hex_digit(presented.get(index).copied().unwrap_or(0));
            let byte = self.token[index / 2];
            let nibble = if index % 2 == 0 {
                byte >> 4
            } else {
                byte & 0x0f
            };
            diff |= digit ^ usize::from(nibble);
        }
        diff == 0
    }
}

/// Redacted, so no `{:?}` anywhere — an options struct, a tracing field,
/// a panic message — can spill the credential into a log.
impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(redacted)")
    }
}

/// The `Bearer ` scheme prefix, matched case-insensitively as RFC 7235
/// requires, and the credential after it. Nothing here touches the
/// secret, so returning early is free.
fn strip_bearer(value: &[u8]) -> Option<&[u8]> {
    const SCHEME: &[u8] = b"bearer ";
    if value.len() < SCHEME.len() {
        return None;
    }
    let (scheme, credential) = value.split_at(SCHEME.len());
    scheme.eq_ignore_ascii_case(SCHEME).then_some(credential)
}

/// Value of one lowercase-hex digit, or [`NOT_A_DIGIT`].
fn hex_digit(c: u8) -> usize {
    match c {
        b'0'..=b'9' => usize::from(c - b'0'),
        b'a'..=b'f' => usize::from(c - b'a') + 10,
        _ => NOT_A_DIGIT,
    }
}

/// Requires this run's bearer on every request it wraps.
///
/// One implementation, shared: `hellas_gateway::run` puts it over the
/// executor-reaching routes and `spawn_metrics_server` puts the same
/// layer over `/metrics`.
#[derive(Clone)]
pub(crate) struct BearerLayer {
    bearer: Arc<Bearer>,
}

impl BearerLayer {
    pub(crate) fn new(bearer: Arc<Bearer>) -> Self {
        Self { bearer }
    }
}

impl<S> Layer<S> for BearerLayer {
    type Service = BearerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerService {
            inner,
            bearer: self.bearer.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct BearerService<S> {
    inner: S,
    bearer: Arc<Bearer>,
}

impl<S, B> Service<Request<B>> for BearerService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<Body>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if !self.bearer.authorizes(request.headers()) {
            // The request never reaches the inner service, so nothing
            // downstream — handler, executor, provenance — observes it.
            return Box::pin(async { Ok(unauthorized()) });
        }
        // Standard tower/axum cloning idiom: own a "ready" clone of the
        // inner service for the spawned future, leave the original behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { inner.call(request).await })
    }
}

/// The refusal. It says what is required and quotes nothing it was
/// given, so a mistyped credential cannot land in a client's log either.
fn unauthorized() -> Response<Body> {
    let mut response = crate::json_error(
        StatusCode::UNAUTHORIZED,
        "this route requires the gateway's per-run credential in `Authorization: Bearer <token>`",
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

/// Resolve `host:port` and refuse to bind anywhere but loopback.
///
/// The address is parsed and its `is_loopback` asked, never spelled
/// against `"127.0.0.1"` or `"localhost"`: `127.0.0.2` is loopback and a
/// spelling check would refuse it, and a `localhost` that resolves off
/// this machine is not loopback however it is spelled.
pub(crate) async fn loopback_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| {
            anyhow::anyhow!("failed to resolve gateway bind address `{host}:{port}`: {err}")
        })?
        .collect();
    let Some(first) = resolved.first().copied() else {
        anyhow::bail!("gateway bind address `{host}:{port}` resolved to no address");
    };
    if let Some(exposed) = resolved.iter().find(|addr| !addr.ip().is_loopback()) {
        anyhow::bail!(
            "refusing to bind the gateway to `{host}:{port}`: it resolves to {}, which is not \
             loopback, and these routes reach the executor",
            exposed.ip()
        );
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    /// A bearer with a known token, so tests can present the right one.
    fn fixed_bearer() -> (Arc<Bearer>, String) {
        let mut token = [0u8; TOKEN_BYTES];
        for (index, byte) in token.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let hex = encode_hex(&token);
        (Arc::new(Bearer { token }), hex)
    }

    fn guarded_router(bearer: Arc<Bearer>) -> Router {
        Router::new()
            .route("/v1/chat/completions", get(|| async { "reached" }))
            .layer(BearerLayer::new(bearer))
    }

    async fn status_of(router: &Router, request: Request<Body>) -> StatusCode {
        router.clone().oneshot(request).await.unwrap().status()
    }

    fn get_request(uri: &str) -> axum::http::request::Builder {
        Request::builder().method("GET").uri(uri)
    }

    #[tokio::test]
    async fn missing_header_is_refused() {
        let (bearer, _) = fixed_bearer();
        let router = guarded_router(bearer);
        let request = get_request("/v1/chat/completions")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_value_is_refused() {
        let (bearer, hex) = fixed_bearer();
        let router = guarded_router(bearer);
        // Same length, one nibble different.
        let mut wrong = hex.clone();
        wrong.replace_range(0..1, "f");
        assert_eq!(wrong.len(), hex.len());
        let request = get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {wrong}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_length_is_refused() {
        let (bearer, hex) = fixed_bearer();
        let router = guarded_router(bearer);
        for credential in [
            String::new(),
            hex[..TOKEN_HEX_LEN - 1].to_string(),
            format!("{hex}0"),
            hex.repeat(3),
        ] {
            let request = get_request("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(&router, request).await,
                StatusCode::UNAUTHORIZED,
                "a {}-character credential was accepted",
                credential.len()
            );
        }
    }

    #[tokio::test]
    async fn right_token_in_a_query_parameter_is_refused() {
        let (bearer, hex) = fixed_bearer();
        let router = guarded_router(bearer);
        for uri in [
            format!("/v1/chat/completions?access_token={hex}"),
            format!("/v1/chat/completions?authorization=Bearer%20{hex}"),
        ] {
            let request = get_request(&uri).body(Body::empty()).unwrap();
            assert_eq!(
                status_of(&router, request).await,
                StatusCode::UNAUTHORIZED,
                "a credential in the query string was accepted: {uri}"
            );
        }
    }

    #[tokio::test]
    async fn right_token_in_another_header_is_refused() {
        let (bearer, hex) = fixed_bearer();
        let router = guarded_router(bearer);
        for name in ["x-api-key", "x-hellas-authorization", "proxy-authorization"] {
            let request = get_request("/v1/chat/completions")
                .header(name, format!("Bearer {hex}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(&router, request).await,
                StatusCode::UNAUTHORIZED,
                "a credential in `{name}` was accepted"
            );
        }
        // And a cookie carrying it is no better.
        let request = get_request("/v1/chat/completions")
            .header(header::COOKIE, format!("authorization=Bearer {hex}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn correct_authorization_bearer_is_accepted() {
        let (bearer, hex) = fixed_bearer();
        let router = guarded_router(bearer);
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let request = get_request("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("{scheme} {hex}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(&router, request).await,
                StatusCode::OK,
                "`{scheme}` with the run's credential was refused"
            );
        }
    }

    /// The clause is about work, and work is what this asserts: every
    /// input length costs the same number of digit steps. This is a
    /// shape assertion, not a timing measurement — a wall-clock test
    /// would be flaky — but it is the shape the clause is about, because
    /// an early `len() !=` return is precisely what would make the counts
    /// differ.
    #[test]
    fn compare_does_not_short_circuit_on_length() {
        let (bearer, hex) = fixed_bearer();
        let mut counts = Vec::new();
        for credential in [
            String::new(),
            "0".to_string(),
            hex[..TOKEN_HEX_LEN - 1].to_string(),
            hex.clone(),
            format!("{hex}{hex}"),
            "z".repeat(4096),
        ] {
            DIGIT_STEPS.store(0, Ordering::Relaxed);
            let _ = bearer.accepts(credential.as_bytes());
            counts.push(DIGIT_STEPS.load(Ordering::Relaxed));
        }
        assert!(
            counts.iter().all(|count| *count == TOKEN_HEX_LEN),
            "digit steps varied with the credential's length: {counts:?}"
        );
    }

    /// Records everything any `tracing` subscriber would be handed, so
    /// the "never logged" clause is asserted rather than merely intended.
    #[derive(Clone, Default)]
    struct Recorder {
        lines: Arc<Mutex<Vec<String>>>,
    }

    struct Collect(String);

    impl tracing::field::Visit for Collect {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            use fmt::Write;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl Recorder {
        fn push(&self, metadata: &tracing::Metadata<'_>, collected: Collect) {
            self.lines.lock().unwrap().push(format!(
                "{} {} {}",
                metadata.target(),
                metadata.name(),
                collected.0
            ));
        }

        fn captured(&self) -> Vec<String> {
            self.lines.lock().unwrap().clone()
        }
    }

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        /// `sometimes`, not the default `always`/`never`, because the
        /// interest cache is global while this subscriber is only the
        /// default on one thread. Cached as `never` by a sibling test
        /// running without a subscriber, the callsite would go quiet and
        /// this test would pass over a credential it never saw.
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let mut collected = Collect(String::new());
            span.record(&mut collected);
            self.push(span.metadata(), collected);
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            let mut collected = Collect(String::new());
            values.record(&mut collected);
            self.lines.lock().unwrap().push(collected.0);
        }

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut collected = Collect(String::new());
            event.record(&mut collected);
            self.push(event.metadata(), collected);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn credential_reaches_no_trace_no_error_body_and_no_debug() {
        let (bearer, hex) = fixed_bearer();

        // `{:?}` is the way a secret usually escapes: a struct holding it
        // is logged whole. This one cannot be.
        assert_eq!(format!("{bearer:?}"), "Bearer(redacted)");
        assert!(!format!("{bearer:?}").contains(&hex));

        let recorder = Recorder::default();
        let guard = tracing::subscriber::set_default(recorder.clone());
        // Drop whatever interest a sibling test's no-op subscriber cached,
        // so these callsites are re-asked and reach the recorder.
        tracing::callsite::rebuild_interest_cache();
        let router = guarded_router(bearer.clone());

        // Every path: accepted, refused for each reason, and the
        // announcement (which finds no tty under `cargo test`).
        let mut bodies = Vec::new();
        let requests = vec![
            get_request("/v1/chat/completions")
                .body(Body::empty())
                .unwrap(),
            get_request("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {hex}"))
                .body(Body::empty())
                .unwrap(),
            get_request("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {hex}extra"))
                .body(Body::empty())
                .unwrap(),
            get_request("/v1/chat/completions")
                .header(header::AUTHORIZATION, "Bearer deadbeef")
                .body(Body::empty())
                .unwrap(),
            get_request(&format!("/v1/chat/completions?access_token={hex}"))
                .body(Body::empty())
                .unwrap(),
            get_request("/v1/chat/completions")
                .header("x-api-key", format!("Bearer {hex}"))
                .body(Body::empty())
                .unwrap(),
        ];
        for request in requests {
            let response = router.clone().oneshot(request).await.unwrap();
            let headers = format!("{:?}", response.headers());
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            bodies.push(headers);
            bodies.push(String::from_utf8_lossy(&body).into_owned());
        }
        bearer.announce();
        drop(guard);

        for line in recorder.captured() {
            assert!(
                !line.contains(&hex),
                "the run's credential reached a trace event: {line}"
            );
        }
        for body in bodies {
            assert!(
                !body.contains(&hex),
                "the run's credential was echoed back to the caller: {body}"
            );
        }
    }

    #[tokio::test]
    async fn loopback_is_decided_by_parsing_not_by_spelling() {
        // `127.0.0.2` is loopback and is not the string `127.0.0.1`, so
        // only a parsed check accepts it.
        for host in ["127.0.0.1", "127.0.0.2", "::1"] {
            let addr = loopback_addr(host, 0)
                .await
                .unwrap_or_else(|err| panic!("`{host}` should be loopback: {err}"));
            assert!(addr.ip().is_loopback());
        }
    }

    #[tokio::test]
    async fn non_loopback_bind_is_refused() {
        for host in ["0.0.0.0", "::", "10.0.0.1", "192.168.1.7"] {
            let Err(err) = loopback_addr(host, 0).await else {
                panic!("`{host}` is not loopback and must be refused");
            };
            assert!(
                err.to_string().contains("not loopback"),
                "unexpected refusal for `{host}`: {err}"
            );
        }
    }
}
