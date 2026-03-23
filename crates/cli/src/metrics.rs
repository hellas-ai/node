use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;

pub fn spawn_metrics_server(port: u16, registry: Arc<Registry>) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                eprintln!("warning: failed to bind metrics server on {addr}: {err}");
                return;
            }
        };

        let app = axum::Router::new()
            .route(
                "/metrics",
                axum::routing::get(
                    move |axum::extract::State(reg): axum::extract::State<Arc<Registry>>| async move {
                        let mut buf = String::new();
                        if encode(&mut buf, &reg).is_err() {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                "failed to encode metrics".to_string(),
                            );
                        }
                        (axum::http::StatusCode::OK, buf)
                    },
                ),
            )
            .with_state(registry);

        info!("prometheus metrics server listening on http://{addr}/metrics");

        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("warning: metrics server failed: {err}");
        }
    });
}
