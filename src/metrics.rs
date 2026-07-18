// metrics.rs — Prometheus-style metrics export endpoint.
//
// Spawns a lightweight HTTP server on a configurable port (default 9090)
// that serves `/metrics` in Prometheus text exposition format.  The endpoint
// is read-only and lock-free — it samples atomic counters from
// `HealthMonitor`, `RiskManager`, and `HighFrequencyExecutionEngine`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{oneshot, RwLock};

use crate::health::HealthMonitor;
use crate::protections::RiskManager;
use crate::execution::HighFrequencyExecutionEngine;

// ---------------------------------------------------------------------------
// Metrics exporter
// ---------------------------------------------------------------------------

/// Configuration for the metrics HTTP endpoint.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Bind address for the metrics server (default "127.0.0.1:9090").
    pub bind_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        // TODO: Make metrics bind address configurable via CLI/env.
        // In production, bind to 127.0.0.1:9090 and use a reverse proxy.
        Self {
            bind_addr: "127.0.0.1:9090".to_string(),
        }
    }
}

/// Shared references needed by the metrics endpoint.
pub struct MetricsState {
    pub health: Arc<HealthMonitor>,
    pub risk: Arc<RiskManager>,
    pub execution: Option<Arc<HighFrequencyExecutionEngine>>,
}

/// Default sample rate: only recompute full metrics on every Nth scrape.
const DEFAULT_SAMPLE_RATE: u64 = 10;

/// Internal sampling state shared across connection handlers.
struct MetricsSampling {
    /// Incremented on every `/metrics` request.
    counter: AtomicU64,
    /// Record 1 in `rate` requests.  Default: `DEFAULT_SAMPLE_RATE`.
    rate: u64,
    /// Cached Prometheus output from the last sampled render.
    cache: RwLock<String>,
}

impl MetricsSampling {
    fn new(sample_rate: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            rate: sample_rate,
            cache: RwLock::new(String::new()),
        }
    }

    /// Returns `true` if this call should perform a full recompute.
    #[inline]
    fn should_sample(&self) -> bool {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        count.is_multiple_of(self.rate)
    }
}

/// Spawn the Prometheus metrics server.
///
/// Returns a `oneshot::Sender` that, when dropped, signals the server to shut
/// down.  The server task runs in the background.
pub fn spawn_metrics_server(
    config: MetricsConfig,
    state: Arc<MetricsState>,
) -> (tokio::task::JoinHandle<()>, oneshot::Sender<()>) {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let sampling = Arc::new(MetricsSampling::new(DEFAULT_SAMPLE_RATE));

    let handle = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
            Ok(l) => {
                tracing::info!(addr = %config.bind_addr, "Prometheus metrics server listening");
                l
            }
            Err(e) => {
                tracing::error!(addr = %config.bind_addr, error = %e, "failed to bind metrics server");
                return;
            }
        };

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            let state = Arc::clone(&state);
                            let sampling = Arc::clone(&sampling);
                            tokio::spawn(async move {
                                handle_connection(stream, &state, &sampling).await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "metrics accept error");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("Prometheus metrics server shutting down");
                    break;
                }
            }
        }
    });

    (handle, shutdown_tx)
}

/// Handle a single HTTP connection — parse the request, write the response.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    state: &MetricsState,
    sampling: &MetricsSampling,
) {
    use tokio::io::AsyncWriteExt;

    let mut buf = [0u8; 1024];
    // We only care about reading the first line to determine the path.
    let _n = match stream.try_read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };

    let request_line = String::from_utf8_lossy(&buf);
    let path = request_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, content_type, body) = if path == "/metrics" {
        // Sampling: only recompute every Nth request; otherwise serve cache.
        if sampling.should_sample() {
            let rendered = render_prometheus(state);
            {
                let mut cache = sampling.cache.write().await;
                *cache = rendered.clone();
            }
            (
                "HTTP/1.1 200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                rendered,
            )
        } else {
            let cache = sampling.cache.read().await;
            (
                "HTTP/1.1 200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                cache.clone(),
            )
        }
    } else {
        (
            "HTTP/1.1 404 Not Found",
            "text/plain; charset=utf-8",
            "Not Found\n".to_string(),
        )
    };

    let response = format!(
        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body,
    );

    let mut stream = stream;
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Render all metrics in Prometheus text exposition format.
fn render_prometheus(state: &MetricsState) -> String {
    let mut out = String::with_capacity(2048);

    // --- Help lines for each metric group ---
    out.push_str("# HELP rust_hft_arb_uptime_seconds Seconds since engine start.\n");
    out.push_str("# TYPE rust_hft_arb_uptime_seconds gauge\n");
    out.push_str(&format!(
        "rust_hft_arb_uptime_seconds {}\n\n",
        state.health.get_uptime_secs()
    ));

    let stats = state.health.get_stats();

    out.push_str("# HELP rust_hft_arb_signals_total Total arbitrage signals generated.\n");
    out.push_str("# TYPE rust_hft_arb_signals_total counter\n");
    out.push_str(&format!("rust_hft_arb_signals_total {}\n\n", stats.total_signals));

    out.push_str("# HELP rust_hft_arb_trades_total Total trades executed.\n");
    out.push_str("# TYPE rust_hft_arb_trades_total counter\n");
    out.push_str(&format!("rust_hft_arb_trades_total {}\n\n", stats.total_trades));

    out.push_str("# HELP rust_hft_arb_errors_total Total trade errors.\n");
    out.push_str("# TYPE rust_hft_arb_errors_total counter\n");
    out.push_str(&format!("rust_hft_arb_errors_total {}\n\n", stats.total_errors));

    out.push_str("# HELP rust_hft_arb_ws_reconnects_total Total WebSocket reconnections.\n");
    out.push_str("# TYPE rust_hft_arb_ws_reconnects_total counter\n");
    out.push_str(&format!("rust_hft_arb_ws_reconnects_total {}\n\n", stats.ws_reconnects));

    out.push_str("# HELP rust_hft_arb_healthy Whether the engine is healthy (1 = healthy, 0 = unhealthy).\n");
    out.push_str("# TYPE rust_hft_arb_healthy gauge\n");
    out.push_str(&format!(
        "rust_hft_arb_healthy {}\n\n",
        if stats.is_healthy { 1 } else { 0 }
    ));

    out.push_str("# HELP rust_hft_arb_last_signal_ago_seconds Seconds since last arbitrage signal.\n");
    out.push_str("# TYPE rust_hft_arb_last_signal_ago_seconds gauge\n");
    out.push_str(&format!("rust_hft_arb_last_signal_ago_seconds {}\n\n", stats.last_signal_ago_secs));

    out.push_str("# HELP rust_hft_arb_last_trade_ago_seconds Seconds since last trade.\n");
    out.push_str("# TYPE rust_hft_arb_last_trade_ago_seconds gauge\n");
    out.push_str(&format!("rust_hft_arb_last_trade_ago_seconds {}\n\n", stats.last_trade_ago_secs));

    // --- Risk metrics ---
    let session_pnl_cents = state.risk.get_session_pnl();
    let session_pnl_usd = session_pnl_cents as f64 / 100.0;

    out.push_str("# HELP rust_hft_arb_session_pnl_usd Current session P&L in USD (cents / 100).\n");
    out.push_str("# TYPE rust_hft_arb_session_pnl_usd gauge\n");
    out.push_str(&format!("rust_hft_arb_session_pnl_usd {:.2}\n\n", session_pnl_usd));

    out.push_str("# HELP rust_hft_arb_killswitch_active Whether the global kill switch is active (1 = active, 0 = inactive).\n");
    out.push_str("# TYPE rust_hft_arb_killswitch_active gauge\n");
    out.push_str(&format!(
        "rust_hft_arb_killswitch_active {}\n\n",
        if state.risk.is_kill_switch_active() { 1 } else { 0 }
    ));

    out.push_str("# HELP rust_hft_arb_rollback_total Total emergency counter-order rollbacks fired.\n");
    out.push_str("# TYPE rust_hft_arb_rollback_total counter\n");

    let rollback_count = state
        .execution
        .as_ref()
        .map(|e| e.get_rollback_count())
        .unwrap_or(0);
    out.push_str(&format!("rust_hft_arb_rollback_total {}\n", rollback_count));

    out
}