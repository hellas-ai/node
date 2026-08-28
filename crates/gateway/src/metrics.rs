use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::access::BearerLayer;

pub(crate) struct MetricsBundle {
    prometheus: Arc<Registry>,
}

impl MetricsBundle {
    pub(crate) fn new(prometheus: Arc<Registry>) -> Self {
        Self { prometheus }
    }
}

/// Where `/metrics` is served, given the operator's `--metrics-port`.
///
/// `None` in, `None` out: metrics is off unless a port is named, and
/// `--metrics-port` has no default. When it is named the address is
/// loopback — [`Ipv4Addr::LOCALHOST`] is a parsed value, not a spelling,
/// and there is no host to configure, so there is nothing to resolve.
pub(crate) fn metrics_binding(metrics_port: Option<u16>) -> Option<SocketAddr> {
    metrics_port.map(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// The metrics endpoint, behind the same credential as the routes that
/// reach the executor — the very same [`BearerLayer`] value, cloned, not
/// a second check that has to be kept in step with the first.
fn metrics_router(bundle: Arc<MetricsBundle>, auth: BearerLayer) -> axum::Router {
    axum::Router::new()
        .route(
            "/metrics",
            axum::routing::get(
                move |axum::extract::State(bundle): axum::extract::State<Arc<MetricsBundle>>| async move {
                    encode_metrics(&bundle)
                        .map(|buf| (axum::http::StatusCode::OK, buf))
                        .unwrap_or((
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to encode metrics".to_string(),
                        ))
                },
            ),
        )
        .with_state(bundle)
        .layer(auth)
}

pub(crate) fn spawn_metrics_server(port: u16, bundle: MetricsBundle, auth: BearerLayer) {
    let Some(addr) = metrics_binding(Some(port)) else {
        return;
    };
    let bundle = Arc::new(bundle);

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("warning: failed to bind metrics server on {addr}: {err}");
                return;
            }
        };

        let app = metrics_router(bundle, auth);

        info!("prometheus metrics server listening on http://{addr}/metrics");

        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("warning: metrics server failed: {err}");
        }
    });
}

fn encode_metrics(bundle: &MetricsBundle) -> Result<String, std::fmt::Error> {
    let mut buf = String::new();
    encode(&mut buf, &bundle.prometheus)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Bearer;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    #[test]
    fn metrics_is_off_unless_a_port_is_named() {
        assert!(metrics_binding(None).is_none());
    }

    #[test]
    fn enabled_metrics_binds_loopback() {
        let addr = metrics_binding(Some(9090)).expect("a named port is served");
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 9090);
    }

    /// The metrics endpoint refuses everything the executor-reaching
    /// routes refuse, because it is the same layer over a different
    /// router — not a second implementation.
    #[tokio::test]
    async fn enabled_metrics_requires_the_same_credential() {
        let bearer = Arc::new(Bearer::generate());
        let credential = bearer.child_credential();
        let registry = Arc::new(Registry::default());
        let router = metrics_router(
            Arc::new(MetricsBundle::new(registry)),
            BearerLayer::new(bearer),
        );

        let refused = [
            // no header at all
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
            // wrong value, right length
            Request::builder()
                .uri("/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {}", "0".repeat(64)))
                .body(Body::empty())
                .unwrap(),
            // wrong length
            Request::builder()
                .uri("/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {credential}0"))
                .body(Body::empty())
                .unwrap(),
            // right token, query parameter
            Request::builder()
                .uri(format!("/metrics?access_token={credential}"))
                .body(Body::empty())
                .unwrap(),
            // right token, wrong header
            Request::builder()
                .uri("/metrics")
                .header("x-api-key", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        ];
        for request in refused {
            let uri = request.uri().clone();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "/metrics served an unauthorized request to {uri}"
            );
        }

        let request = Request::builder()
            .uri("/metrics")
            .header(header::AUTHORIZATION, format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains(&credential),
            "the credential appeared in a metrics label"
        );
    }
}
