use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) struct MetricsBundle {
    prometheus: Arc<Registry>,
}

impl MetricsBundle {
    pub(crate) fn new(prometheus: Arc<Registry>) -> Self {
        Self { prometheus }
    }
}

pub(crate) fn spawn_metrics_server(port: u16, bundle: MetricsBundle) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let bundle = Arc::new(bundle);

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("warning: failed to bind metrics server on {addr}: {err}");
                return;
            }
        };

        let app = axum::Router::new()
            .route(
                "/metrics",
                axum::routing::get(
                    move |axum::extract::State(bundle): axum::extract::State<
                        Arc<MetricsBundle>,
                    >| async move {
                        encode_metrics(&bundle)
                            .map(|buf| (axum::http::StatusCode::OK, buf))
                            .unwrap_or((
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                "failed to encode metrics".to_string(),
                            ))
                    },
                ),
            )
            .with_state(bundle);

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
