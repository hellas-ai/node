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
mod tests;
