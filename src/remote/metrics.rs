//! Lightweight Prometheus-text metrics for the reverse remote instance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Snapshot-friendly counters / gauges for observability.
#[derive(Default)]
struct Inner {
    /// (group, result) -> count  result = ok|unauthorized|not_found|error
    registrations: HashMap<(String, String), u64>,
    /// group -> active clients
    active_clients: HashMap<String, i64>,
    /// (host, group, status) -> count
    proxy_requests: HashMap<(String, String, u16), u64>,
    /// (host, group) -> (count, total_micros)
    proxy_latency: HashMap<(String, String), (u64, u64)>,
    /// total accepted QUIC connections
    quic_accepts: u64,
    /// HTTP requests that failed before a status (framing/proxy errors)
    proxy_errors: u64,
}

#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Mutex<Inner>>,
    started: Arc<Instant>,
    /// Fast path counter for scrape without lock contention on hot path optionals
    requests_total: Arc<AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            started: Arc::new(Instant::now()),
            requests_total: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn quic_accepted(&self) {
        let mut g = self.inner.lock().unwrap();
        g.quic_accepts += 1;
    }

    pub fn registration(&self, group: &str, result: &str) {
        let mut g = self.inner.lock().unwrap();
        *g.registrations
            .entry((group.to_string(), result.to_string()))
            .or_insert(0) += 1;
    }

    pub fn client_registered(&self, group: &str) {
        let mut g = self.inner.lock().unwrap();
        *g.active_clients.entry(group.to_string()).or_insert(0) += 1;
    }

    pub fn client_unregistered(&self, group: &str) {
        let mut g = self.inner.lock().unwrap();
        let e = g.active_clients.entry(group.to_string()).or_insert(0);
        *e = (*e - 1).max(0);
    }

    pub fn proxy_request(&self, host: &str, group: &str, status: u16, elapsed: std::time::Duration) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.lock().unwrap();
        *g.proxy_requests
            .entry((host.to_string(), group.to_string(), status))
            .or_insert(0) += 1;
        let slot = g
            .proxy_latency
            .entry((host.to_string(), group.to_string()))
            .or_insert((0, 0));
        slot.0 += 1;
        slot.1 += elapsed.as_micros() as u64;
    }

    pub fn proxy_error(&self) {
        let mut g = self.inner.lock().unwrap();
        g.proxy_errors += 1;
    }

    /// Render Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let g = self.inner.lock().unwrap();
        let mut out = String::new();

        out.push_str("# HELP sirang_up Sirang remote process is up\n");
        out.push_str("# TYPE sirang_up gauge\n");
        out.push_str("sirang_up 1\n");

        out.push_str("# HELP sirang_uptime_seconds Seconds since remote process start\n");
        out.push_str("# TYPE sirang_uptime_seconds gauge\n");
        out.push_str(&format!(
            "sirang_uptime_seconds {}\n",
            self.started.elapsed().as_secs_f64()
        ));

        out.push_str("# HELP sirang_quic_connections_accepted_total QUIC connections accepted\n");
        out.push_str("# TYPE sirang_quic_connections_accepted_total counter\n");
        out.push_str(&format!(
            "sirang_quic_connections_accepted_total {}\n",
            g.quic_accepts
        ));

        out.push_str("# HELP sirang_tunnel_group_registrations_total Tunnel group registration attempts\n");
        out.push_str("# TYPE sirang_tunnel_group_registrations_total counter\n");
        for ((group, result), n) in &g.registrations {
            out.push_str(&format!(
                "sirang_tunnel_group_registrations_total{{group=\"{}\",result=\"{}\"}} {}\n",
                escape(group),
                escape(result),
                n
            ));
        }

        out.push_str("# HELP sirang_tunnel_group_active_clients Active registered clients per group\n");
        out.push_str("# TYPE sirang_tunnel_group_active_clients gauge\n");
        for (group, n) in &g.active_clients {
            out.push_str(&format!(
                "sirang_tunnel_group_active_clients{{group=\"{}\"}} {}\n",
                escape(group),
                n
            ));
        }

        out.push_str("# HELP sirang_proxy_requests_total Proxied HTTP requests by host, group, status\n");
        out.push_str("# TYPE sirang_proxy_requests_total counter\n");
        for ((host, group, status), n) in &g.proxy_requests {
            out.push_str(&format!(
                "sirang_proxy_requests_total{{host=\"{}\",group=\"{}\",status=\"{}\"}} {}\n",
                escape(host),
                escape(group),
                status,
                n
            ));
        }

        out.push_str("# HELP sirang_proxy_request_duration_microseconds_sum Total proxy latency\n");
        out.push_str("# TYPE sirang_proxy_request_duration_microseconds_sum counter\n");
        out.push_str("# HELP sirang_proxy_request_duration_microseconds_count Proxy request count for latency\n");
        out.push_str("# TYPE sirang_proxy_request_duration_microseconds_count counter\n");
        for ((host, group), (count, micros)) in &g.proxy_latency {
            out.push_str(&format!(
                "sirang_proxy_request_duration_microseconds_sum{{host=\"{}\",group=\"{}\"}} {}\n",
                escape(host),
                escape(group),
                micros
            ));
            out.push_str(&format!(
                "sirang_proxy_request_duration_microseconds_count{{host=\"{}\",group=\"{}\"}} {}\n",
                escape(host),
                escape(group),
                count
            ));
        }

        out.push_str("# HELP sirang_proxy_errors_total Proxy/framing errors\n");
        out.push_str("# TYPE sirang_proxy_errors_total counter\n");
        out.push_str(&format!("sirang_proxy_errors_total {}\n", g.proxy_errors));

        out.push_str("# HELP sirang_proxy_requests_inflight_total Fast counter of all proxy attempts\n");
        out.push_str("# TYPE sirang_proxy_requests_inflight_total counter\n");
        out.push_str(&format!(
            "sirang_proxy_requests_inflight_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));

        out
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Serve Prometheus metrics and health on the management address.
pub async fn serve_management(
    addr: std::net::SocketAddr,
    metrics: Metrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr).await?;
    log::info!("Management / metrics listening on {addr} (GET /metrics, GET /healthz)");

    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let metrics = metrics.clone();
                async move {
                    let path = req.uri().path();
                    let res = match (req.method(), path) {
                        (&Method::GET, "/metrics") => {
                            let body = metrics.render_prometheus();
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap()
                        }
                        (&Method::GET, "/healthz") | (&Method::GET, "/health") => Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "text/plain")
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                        _ => Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from_static(b"not found")))
                            .unwrap(),
                    };
                    Ok::<_, std::convert::Infallible>(res)
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
