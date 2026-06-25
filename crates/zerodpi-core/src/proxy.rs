//! tokio-based TCP proxy that drives the bypass:
//!
//! For interceptor-based methods (`wrong_seq`, `wrong_ack`, `wrong_checksum`,
//! `wrong_md5`, `wrong_seq_wrong_md5`, `wrong_timestamp`, `tls_record_frag`,
//! `wrong_seq_tls_frag`, `wrong_md5_tls_frag`, `wrong_seq_tls_record_frag`):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Open an outbound TCP socket bound to the local interface IP.
//! 3. Build a fake ClientHello and register the flow in the [`FlowTable`].
//! 4. The platform interceptor observes the handshake and either completes the
//!    fake-packet bypass or asks the proxy to write the first ClientHello while
//!    the flow is still being intercepted.
//! 5. Once the bypass completes, the proxy runs a normal bidirectional copy
//!    between the two sockets.
//! 6. For `wrong_seq_tls_frag` and `wrong_md5_tls_frag`, step 4 writes the
//!    intact ClientHello in small TCP segments using the same `TCP_SEG_*`
//!    settings as `tls_frag`.
//!
//! For `ip_bypass_plus`, IP scanning selects the upstream IPv4 address, then
//! only real-SNI-preserving methods (`tls_record_frag` or `tls_frag`)
//! are applied to the first ClientHello. No fake SNI payload is generated.
//!
//! For socket-based methods (`tls_frag`, TCP-level TLS Fragment):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Connect to the upstream server (no FlowTable registration, no interceptor).
//! 3. Read one complete TLS record (the ClientHello) from the client socket.
//! 4. Write the intact TLS record to the upstream socket in tiny chunks with
//!    `TCP_NODELAY` so each chunk arrives as a separate TCP segment.
//! 5. Hand off to the normal bidirectional relay.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::flow::{BypassOutcome, FlowEntry, FlowKey, FlowTable};
use crate::ip_scanner::IpScanEvent;
use crate::methods::tcp_segmentation::{read_one_tls_record, write_segmented, TcpSegmentation};
use crate::tls_template::build_client_hello;

// ---------------------------------------------------------------------------
// Active SNI target
// ---------------------------------------------------------------------------

/// Currently selected SNI-spoof target. The proxy snapshots this once per new
/// connection, so background switches affect new connections only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSniTarget {
    pub sni: Arc<str>,
    pub ip: Ipv4Addr,
    pub score: u8,
}

impl ActiveSniTarget {
    pub fn new(sni: impl Into<Arc<str>>, ip: Ipv4Addr, score: u8) -> Self {
        Self {
            sni: sni.into(),
            ip,
            score,
        }
    }
}

pub type SharedSniTarget = Arc<RwLock<ActiveSniTarget>>;

// ---------------------------------------------------------------------------
// Proxy events
// ---------------------------------------------------------------------------

/// Events emitted by the proxy for each connection, used to drive the live
/// dashboard when running in interactive mode.
#[derive(Debug)]
pub enum ProxyEvent {
    /// A new inbound connection was accepted and the outbound source port is known.
    ConnectionAccepted { peer: SocketAddr, src_port: u16 },
    /// The SNI-bypass phase finished (successfully or not).
    BypassComplete {
        src_port: u16,
        outcome: BypassOutcome,
    },
    /// The bidirectional relay ended.
    ///
    /// `c2s_bytes` and `s2c_bytes` are the bytes transferred in each direction.
    /// They include bytes copied before a configured max-lifetime rotation.
    RelayFinished {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
        reason: RelayEndReason,
    },
    /// A fatal error occurred before the relay could start (e.g. upstream
    /// TCP connect failed).
    ConnectionError { src_port: u16, error: String },
    /// Periodic progress report while the relay is running (emitted every 500 ms).
    RelayProgress {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
    },
    /// The active SNI-spoof target changed after a background rescan.
    SniTargetChanged {
        sni: String,
        ip: Ipv4Addr,
        score: u8,
    },
    /// The active IP-bypass target changed after a background rescan.
    IpTargetChanged { ip: IpAddr },
}

/// Sender half of the [`ProxyEvent`] channel; pass to [`run_proxy`] to enable
/// the live dashboard.  When `None` is passed the proxy operates silently.
pub type ProxyEventSender = mpsc::UnboundedSender<ProxyEvent>;

/// Why a relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEndReason {
    /// Both relay directions ended naturally.
    Completed,
    /// The configured maximum relay lifetime expired and the relay was closed
    /// so the upstream client can reconnect through the current target.
    MaxLifetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayResult {
    c2s_bytes: u64,
    s2c_bytes: u64,
    reason: RelayEndReason,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tcp_seg_size: usize,
    tcp_seg_nodelay: bool,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: method_segments_first_client_hello(&cfg.BYPASS_METHOD),
            tcp_seg_size: tcp_segmentation.seg_size,
            tcp_seg_nodelay: tcp_segmentation.nodelay,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BypassProgress {
    ReadyForData,
    Complete(BypassOutcome),
}

#[derive(Debug)]
struct InterceptConnectionTarget {
    interface_ip: Ipv4Addr,
    connect_ip: Ipv4Addr,
    fake_client_hello: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a [`ProxyEvent`] if a sender is present; silently drop if not.
#[inline]
fn emit(tx: &Option<ProxyEventSender>, event: ProxyEvent) {
    if let Some(ref tx) = tx {
        let _ = tx.send(event);
    }
}

fn configured_relay_max_lifetime(cfg: &Config) -> Option<Duration> {
    (cfg.RELAY_MAX_LIFETIME_SECS > 0).then(|| Duration::from_secs(cfg.RELAY_MAX_LIFETIME_SECS))
}

/// How long to wait for the bypass to complete before giving up.
/// This constant is kept for use in tests; the proxy uses `cfg.BYPASS_TIMEOUT_SECS`.
pub const BYPASS_TIMEOUT: Duration = Duration::from_secs(2);

/// The upstream port — always 443.
pub const CONNECT_PORT: u16 = 443;

/// Build the spoofed ClientHello payload for one new flow.
pub fn fresh_fake_client_hello(fake_sni: &[u8]) -> Vec<u8> {
    use rand_lite::random32;
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    random32(&mut random);
    random32(&mut session_id);
    random32(&mut key_share);
    build_client_hello(&random, &session_id, fake_sni, &key_share)
}

fn current_bypass_progress(entry: &FlowEntry) -> Option<BypassProgress> {
    let state = entry.state.lock();
    if let Some(outcome) = state.outcome {
        Some(BypassProgress::Complete(outcome))
    } else if state.waiting_for_data {
        Some(BypassProgress::ReadyForData)
    } else {
        None
    }
}

fn method_segments_first_client_hello(method: &str) -> bool {
    matches!(method, "wrong_seq_tls_frag" | "wrong_md5_tls_frag")
}

async fn wait_for_initial_bypass_progress(
    entry: &FlowEntry,
    timeout: Duration,
) -> Option<BypassProgress> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(progress) = current_bypass_progress(entry) {
                return progress;
            }
            tokio::select! {
                _ = entry.notify.notified() => {}
                _ = entry.ready_for_data.notified() => {}
            }
        }
    })
    .await
    .ok()
}

async fn wait_for_bypass_completion(entry: &FlowEntry, timeout: Duration) -> Option<BypassOutcome> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(outcome) = entry.state.lock().outcome {
                return outcome;
            }
            entry.notify.notified().await;
        }
    })
    .await
    .ok()
}

fn finish_bypass_or_error(
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    outcome: Option<BypassOutcome>,
    timeout_error: &'static str,
) -> anyhow::Result<()> {
    match outcome {
        Some(BypassOutcome::FakeDataAcked) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::FakeDataAcked,
                },
            );
            Ok(())
        }
        Some(BypassOutcome::UnexpectedClose) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("interceptor closed the flow");
        }
        None => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!(timeout_error);
        }
    }
}

/// A tiny inline RNG so we don't pull in the `rand` crate just for 96 bytes
/// of nonce material per connection. Seeded from system time + an atomic
/// counter; quality is good enough for nonces (not for crypto-strong key
/// generation, but the spoofed ClientHello is discarded by the server).
mod rand_lite {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn random32(buf: &mut [u8]) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut state = nanos
            ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            ^ (buf.as_ptr() as usize as u64);
        for chunk in buf.chunks_mut(8) {
            // splitmix64
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            for (b, s) in chunk.iter_mut().zip(bytes.iter()) {
                *b = *s;
            }
        }
    }
}

/// Run the proxy: bind the listener and accept connections forever.
///
/// Each accepted connection is handled on its own tokio task; the platform
/// interceptor (running on a dedicated OS thread) is expected to be looking
/// at the same `flows` table.
///
/// Pass `Some(sender)` to receive [`ProxyEvent`] notifications for the live
/// dashboard; pass `None` when no dashboard is attached.
pub async fn run_proxy(
    cfg: Arc<Config>,
    active_target: SharedSniTarget,
    interface_ip: Ipv4Addr,
    flows: FlowTable,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, "listening");

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        debug!(%peer, "accepted");

        // Route to the socket-based path for tls_frag.
        // No FlowTable registration; no interceptor involvement.
        if cfg.BYPASS_METHOD == "tls_frag" {
            let cfg = cfg.clone();
            let connect_ip = active_target.read().unwrap().ip;
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx)
                        .await
                {
                    warn!(%peer, error = %e, "tls_frag connection failed");
                }
            });
            continue;
        }

        let target = active_target.read().unwrap().clone();
        let flows = flows.clone();
        let event_tx = event_tx.clone();
        let connection_settings = ConnectionSettings::from_config(&cfg);
        let fake_client_hello = fresh_fake_client_hello(target.sni.as_bytes());
        tokio::spawn(async move {
            if let Err(e) = handle_intercept_connection(
                InterceptConnectionTarget {
                    interface_ip,
                    connect_ip: target.ip,
                    fake_client_hello,
                },
                flows,
                incoming,
                peer,
                event_tx,
                connection_settings,
            )
            .await
            {
                warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}

async fn handle_intercept_connection(
    target: InterceptConnectionTarget,
    flows: FlowTable,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
    settings: ConnectionSettings,
) -> anyhow::Result<()> {
    let connect_port = CONNECT_PORT;
    let interface_ip = target.interface_ip;
    let connect_ip = target.connect_ip;

    // Build outbound socket bound to the host's interface IP, kernel-chosen port.
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((interface_ip, 0)))?;
    let local = socket.local_addr()?;
    let src_port = local.port();

    // Now that we have the source port, report the accepted connection.
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let key = FlowKey {
        src_ip: interface_ip,
        src_port,
        dst_ip: connect_ip,
        dst_port: connect_port,
    };

    let entry = FlowEntry::new(target.fake_client_hello);
    flows.insert(key, entry.clone());

    // Make sure we always remove the entry on this path's exit.
    let cleanup = scopeguard(|| {
        flows.remove(&key);
    });

    // Connect: while this is happening, the kernel emits SYN, receives SYN-ACK,
    // and sends the bare ACK that the interceptor will rewrite.
    let mut outgoing = match socket
        .connect(SocketAddr::from((connect_ip, connect_port)))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("connect upstream");
        }
    };

    // Wait until the interceptor either completes a fake-packet bypass or asks
    // us to send the first real ClientHello while the flow is still tracked.
    match wait_for_initial_bypass_progress(&entry, settings.bypass_timeout).await {
        Some(BypassProgress::Complete(outcome)) => {
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                Some(outcome),
                "bypass timed out",
            )?;
        }
        Some(BypassProgress::ReadyForData) => {
            let client_hello = match tokio::time::timeout(
                settings.bypass_timeout,
                read_one_tls_record(&mut incoming),
            )
            .await
            {
                Ok(Ok(record)) => record,
                Ok(Err(e)) => {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("reading ClientHello from client");
                }
                Err(_) => {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    anyhow::bail!("timed out reading ClientHello from client");
                }
            };

            if settings.segment_first_client_hello {
                if settings.tcp_seg_nodelay {
                    outgoing
                        .set_nodelay(true)
                        .context("combo tls_frag: set_nodelay on upstream socket")?;
                }
                if let Err(e) =
                    write_segmented(&mut outgoing, &client_hello, settings.tcp_seg_size).await
                {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("combo tls_frag: writing segmented ClientHello");
                }
            } else {
                if let Err(e) = outgoing.write_all(&client_hello).await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("writing ClientHello to upstream");
                }
                if let Err(e) = outgoing.flush().await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("flushing ClientHello to upstream");
                }
            }

            let outcome = wait_for_bypass_completion(&entry, settings.bypass_timeout).await;
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                outcome,
                "first data bypass timed out",
            )?;
        }
        None => {
            finish_bypass_or_error(&entry, &event_tx, src_port, None, "bypass timed out")?;
        }
    }

    debug!(?key, "bypass complete");

    // Release the flow before relaying so any further packets pass through.
    drop(cleanup);

    // Bidirectional relay with periodic progress events.
    let relay = counting_relay(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        settings.max_lifetime,
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// IP-bypass-plus proxy (IP selection + real-SNI-preserving bypass methods)
// ---------------------------------------------------------------------------

/// Run the IP-bypass-plus proxy.
///
/// The active target is an IP selected by the IP scanner, like `ip_bypass`.
/// Unlike plain `ip_bypass`, this mode may apply a real-SNI-preserving
/// ClientHello bypass method:
///
/// - `tls_frag`: socket-only segmentation, no packet interceptor.
/// - `tls_record_frag`: packet interceptor rewrites the first real ClientHello
///   into TLS record fragments. The flow stores an empty fake payload because
///   no fake SNI packet is emitted.
///
/// This mode is intentionally IPv4-only so the interceptor path can use the
/// existing IPv4 flow tracking and platform filters.
pub async fn run_ip_bypass_plus_proxy(
    cfg: Arc<Config>,
    active_ip: Arc<RwLock<IpAddr>>,
    interface_ip: Ipv4Addr,
    flows: FlowTable,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, method = %cfg.BYPASS_METHOD, "ip_bypass_plus: listening");

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "ip_bypass_plus: accept failed");
                continue;
            }
        };
        debug!(%peer, "ip_bypass_plus: accepted");

        let connect_ip = match *active_ip.read().unwrap() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => {
                warn!(%ip, "ip_bypass_plus: active IPv6 target rejected");
                continue;
            }
        };

        if cfg.BYPASS_METHOD == "tls_frag" {
            let cfg = cfg.clone();
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx)
                        .await
                {
                    warn!(%peer, error = %e, "ip_bypass_plus tls_frag connection failed");
                }
            });
            continue;
        }

        let flows = flows.clone();
        let event_tx = event_tx.clone();
        let connection_settings = ConnectionSettings::from_config(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_intercept_connection(
                InterceptConnectionTarget {
                    interface_ip,
                    connect_ip,
                    fake_client_hello: Vec::new(),
                },
                flows,
                incoming,
                peer,
                event_tx,
                connection_settings,
            )
            .await
            {
                warn!(%peer, error = %e, "ip_bypass_plus connection failed");
            }
        });
    }
}

/// Tiny scope-guard so we don't pull in the `scopeguard` crate.
fn scopeguard<F: FnOnce()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(Some(f))
}
struct ScopeGuard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// tls_frag proxy path (no packet interceptor)
// ---------------------------------------------------------------------------

/// Handle a single connection using the `tls_frag` bypass method.
///
/// Does **not** register a flow in the [`FlowTable`] and does **not** involve
/// the platform packet interceptor.  Instead:
///
/// 1. Connects to the upstream server (with `TCP_NODELAY` if configured).
/// 2. Reads exactly one complete TLS record from the client — the ClientHello.
/// 3. Writes it to the upstream socket in chunks of `TCP_SEG_SIZE` bytes.
///    With `TCP_NODELAY` each chunk is sent as a separate TCP segment.
/// 4. Hands off to the normal bidirectional relay.
async fn handle_tcp_seg_connection_with_ip(
    cfg: Arc<Config>,
    connect_ip: Ipv4Addr,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let src_port = peer.port();
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let method = TcpSegmentation::new(&cfg);
    let connect_addr = SocketAddr::from((connect_ip, CONNECT_PORT));

    // Connect to upstream.
    let mut outgoing = match TcpStream::connect(connect_addr).await {
        Ok(s) => s,
        Err(e) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("tls_frag: connect upstream");
        }
    };

    // Enable TCP_NODELAY on the upstream socket if configured.
    if method.nodelay {
        outgoing
            .set_nodelay(true)
            .context("tls_frag: set_nodelay on upstream socket")?;
    }

    // Read exactly one TLS record (the ClientHello) from the client.
    let client_hello = read_one_tls_record(&mut incoming)
        .await
        .context("tls_frag: reading ClientHello from client")?;

    // Write it to the upstream socket in small segments.
    write_segmented(&mut outgoing, &client_hello, method.seg_size)
        .await
        .context("tls_frag: writing segmented ClientHello")?;

    debug!(
        seg_size = method.seg_size,
        nodelay = method.nodelay,
        total_bytes = client_hello.len(),
        "tls_frag: ClientHello written in segments; handing off to relay"
    );

    emit(
        &event_tx,
        ProxyEvent::BypassComplete {
            src_port,
            outcome: BypassOutcome::FakeDataAcked,
        },
    );

    // Bidirectional relay for the rest of the session.
    // The ClientHello has already been forwarded; the relay starts mid-stream.
    let relay = counting_relay(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        configured_relay_max_lifetime(&cfg),
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "tls_frag: relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Counting relay
// ---------------------------------------------------------------------------

/// Run a bidirectional relay between `incoming` and `outgoing`, emitting
/// [`ProxyEvent::RelayProgress`] every 500 ms when a sender is present.
///
/// Returns the total bytes transferred in each direction plus the reason the
/// relay ended.  Shutdown of each write half is handled internally when the
/// corresponding read half reaches EOF.
async fn counting_relay(
    incoming: TcpStream,
    outgoing: TcpStream,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    max_lifetime: Option<Duration>,
) -> RelayResult {
    let (inc_rd, inc_wr) = incoming.into_split();
    let (out_rd, out_wr) = outgoing.into_split();

    let c2s_atomic = Arc::new(AtomicU64::new(0));
    let s2c_atomic = Arc::new(AtomicU64::new(0));

    let mut c2s_task = tokio::spawn(copy_counting(inc_rd, out_wr, c2s_atomic.clone()));
    let mut s2c_task = tokio::spawn(copy_counting(out_rd, inc_wr, s2c_atomic.clone()));

    // Progress ticker — only spawned in interactive mode.
    let ticker = event_tx.as_ref().map(|tx| {
        let tx = tx.clone();
        let c = c2s_atomic.clone();
        let s = s2c_atomic.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let _ = tx.send(ProxyEvent::RelayProgress {
                    src_port,
                    c2s_bytes: c.load(Ordering::Relaxed),
                    s2c_bytes: s.load(Ordering::Relaxed),
                });
            }
        })
    });

    let result = if let Some(max_lifetime) = max_lifetime {
        let mut c2s_done: Option<u64> = None;
        let mut s2c_done: Option<u64> = None;
        let deadline = tokio::time::sleep(max_lifetime);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    if c2s_done.is_none() {
                        c2s_task.abort();
                    }
                    if s2c_done.is_none() {
                        s2c_task.abort();
                    }
                    break RelayResult {
                        c2s_bytes: c2s_done.unwrap_or_else(|| c2s_atomic.load(Ordering::Relaxed)),
                        s2c_bytes: s2c_done.unwrap_or_else(|| s2c_atomic.load(Ordering::Relaxed)),
                        reason: RelayEndReason::MaxLifetime,
                    };
                }
                c2s_result = &mut c2s_task, if c2s_done.is_none() => {
                    c2s_done = Some(c2s_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
                s2c_result = &mut s2c_task, if s2c_done.is_none() => {
                    s2c_done = Some(s2c_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
            }
        }
    } else {
        let (c2s_result, s2c_result) = tokio::join!(c2s_task, s2c_task);
        RelayResult {
            c2s_bytes: c2s_result.unwrap_or(0),
            s2c_bytes: s2c_result.unwrap_or(0),
            reason: RelayEndReason::Completed,
        }
    };

    if let Some(t) = ticker {
        t.abort();
    }

    result
}

/// Copy all bytes from `reader` to `writer`, updating `counter` after each
/// chunk.  Shuts down `writer` gracefully on EOF or error, then returns the
/// total bytes copied.
async fn copy_counting(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

/// Copy with dual counters: cumulative + per-cycle.
async fn copy_counting_dual(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    cumulative: Arc<AtomicU64>,
    cycle: Arc<AtomicU64>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        cumulative.store(total, Ordering::Relaxed);
        cycle.fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

// ---------------------------------------------------------------------------
// IP-bypass proxy (no packet interception, no SNI manipulation)
// ---------------------------------------------------------------------------

/// Run the IP-bypass proxy.
///
/// Unlike [`run_proxy`], this function performs **no packet interception**.
/// It simply accepts incoming TCP connections and relays them to whichever
/// IP is currently stored in `active_ip:443`, forwarding all data verbatim
/// so that the upstream app's own TLS SNI passes through unchanged.
///
/// `active_ip` is an `Arc<RwLock<IpAddr>>` that can be hot-swapped by the
/// background rescan task — each new accepted connection reads the current
/// value, so the swap applies to new connections only.
pub async fn run_ip_bypass_proxy(
    cfg: Arc<Config>,
    active_ip: Arc<RwLock<IpAddr>>,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, "ip_bypass: listening");

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "ip_bypass: accept failed");
                continue;
            }
        };
        debug!(%peer, "ip_bypass: accepted");

        let ip = *active_ip.read().unwrap();
        let event_tx = event_tx.clone();
        let src_port = peer.port();
        let relay_max_lifetime = configured_relay_max_lifetime(&cfg);

        tokio::spawn(async move {
            if let Err(e) = handle_ip_bypass_connection(
                ip,
                incoming,
                peer,
                src_port,
                event_tx,
                relay_max_lifetime,
            )
            .await
            {
                warn!(%peer, error = %e, "ip_bypass: connection failed");
            }
        });
    }
}

async fn handle_ip_bypass_connection(
    connect_ip: IpAddr,
    incoming: TcpStream,
    peer: SocketAddr,
    src_port: u16,
    event_tx: Option<ProxyEventSender>,
    relay_max_lifetime: Option<Duration>,
) -> anyhow::Result<()> {
    let connect_addr = SocketAddr::new(connect_ip, CONNECT_PORT);
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let outgoing = match TcpStream::connect(connect_addr).await {
        Ok(s) => {
            // Reuse BypassComplete / FakeDataAcked to signal "TCP connect OK".
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: crate::flow::BypassOutcome::FakeDataAcked,
                },
            );
            s
        }
        Err(e) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("ip_bypass: connect upstream");
        }
    };

    let relay = counting_relay(incoming, outgoing, &event_tx, src_port, relay_max_lifetime).await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "ip_bypass: relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// find_ip mode: live proxy with dynamic IP pool
// ---------------------------------------------------------------------------

use crate::ip_scanner::IpProbeEntry;

/// Round-robin IP pool for the find_ip live proxy.
pub struct IpPool {
    active: Vec<IpAddr>,
    fixed_ip: Option<IpAddr>,
    next_idx: usize,
    start_times: std::collections::HashMap<IpAddr, std::time::Instant>,
    /// How many cycle_manager cycles each IP has been in the pool.
    cycle_counts: std::collections::HashMap<IpAddr, u64>,
}

impl IpPool {
    pub fn new(initial_ips: Vec<IpAddr>) -> Self {
        let now = std::time::Instant::now();
        let start_times = initial_ips.iter().map(|&ip| (ip, now)).collect();
        let cycle_counts = initial_ips.iter().map(|&ip| (ip, 1u64)).collect();
        Self {
            active: initial_ips,
            fixed_ip: None,
            next_idx: 0,
            start_times,
            cycle_counts,
        }
    }

    pub fn next_ip(&mut self) -> Option<IpAddr> {
        if let Some(fixed) = self.fixed_ip {
            return Some(fixed);
        }
        if self.active.is_empty() {
            return None;
        }
        let ip = self.active[self.next_idx % self.active.len()];
        self.next_idx += 1;
        Some(ip)
    }

    pub fn remove_ip(&mut self, ip: &IpAddr) {
        self.active.retain(|a| a != ip);
    }

    pub fn add_ip(&mut self, ip: IpAddr) {
        if !self.active.contains(&ip) {
            self.active.push(ip);
            self.start_times.insert(ip, std::time::Instant::now());
            self.cycle_counts.insert(ip, 0);
        }
    }

    pub fn fix_ip(&mut self, ip: IpAddr) {
        self.fixed_ip = Some(ip);
        self.active = vec![ip];
        self.next_idx = 0;
    }

    pub fn is_fixed(&self) -> bool {
        self.fixed_ip.is_some()
    }

    pub fn active_ips(&self) -> &[IpAddr] {
        &self.active
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn fixed_ip(&self) -> Option<IpAddr> {
        self.fixed_ip
    }

    pub fn start_time(&self, ip: &IpAddr) -> std::time::Instant {
        self.start_times
            .get(ip)
            .copied()
            .unwrap_or_else(std::time::Instant::now)
    }

    pub fn cycle_count(&self, ip: &IpAddr) -> u64 {
        self.cycle_counts.get(ip).copied().unwrap_or(1)
    }

    /// Update cycle counts based on elapsed time since pool creation.
    pub fn update_cycle_counts(&mut self, cycle_secs: u64) {
        if cycle_secs == 0 { return; }
        let now = std::time::Instant::now();
        for ip in &self.active {
            if let Some(&start) = self.start_times.get(ip) {
                let elapsed = now.duration_since(start).as_secs();
                let cycles = (elapsed / cycle_secs) + 1;
                self.cycle_counts.insert(*ip, cycles);
            }
        }
    }
}

/// Per-IP byte counters: tracks upload, download, and connection count.
pub struct IpByteCountersInner {
    pub upload: DashMap<IpAddr, Arc<AtomicU64>>,
    pub download: DashMap<IpAddr, Arc<AtomicU64>>,
    pub connections: DashMap<IpAddr, Arc<AtomicU64>>,
    /// Per-cycle upload snapshot (reset each cycle).
    pub cycle_upload: DashMap<IpAddr, Arc<AtomicU64>>,
    /// Per-cycle download snapshot (reset each cycle).
    pub cycle_download: DashMap<IpAddr, Arc<AtomicU64>>,
}

pub type IpByteCounters = Arc<IpByteCountersInner>;

impl Default for IpByteCountersInner {
    fn default() -> Self {
        Self::new()
    }
}

impl IpByteCountersInner {
    pub fn new() -> Self {
        Self {
            upload: DashMap::new(),
            download: DashMap::new(),
            connections: DashMap::new(),
            cycle_upload: DashMap::new(),
            cycle_download: DashMap::new(),
        }
    }
    pub fn get_upload(&self, ip: &IpAddr) -> Arc<AtomicU64> {
        self.upload
            .entry(*ip)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    }
    pub fn get_download(&self, ip: &IpAddr) -> Arc<AtomicU64> {
        self.download
            .entry(*ip)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    }
    pub fn inc_connection(&self, ip: &IpAddr) {
        self.connections
            .entry(*ip)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .fetch_add(1, Ordering::Relaxed);
    }
    /// Read total bytes without resetting (cumulative lifetime values).
    pub fn total_bytes(&self, ip: &IpAddr) -> (u64, u64) {
        let upload = self.upload.get(ip).map(|u| u.load(Ordering::Relaxed)).unwrap_or(0);
        let download = self.download.get(ip).map(|d| d.load(Ordering::Relaxed)).unwrap_or(0);
        (upload, download)
    }
    pub fn connection_count(&self, ip: &IpAddr) -> u64 {
        self.connections.get(ip).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
    }
    /// Get per-cycle upload bytes for an IP.
    pub fn cycle_upload_bytes(&self, ip: &IpAddr) -> u64 {
        self.cycle_upload.get(ip).map(|u| u.load(Ordering::Relaxed)).unwrap_or(0)
    }
    /// Get per-cycle download bytes for an IP.
    pub fn cycle_download_bytes(&self, ip: &IpAddr) -> u64 {
        self.cycle_download.get(ip).map(|d| d.load(Ordering::Relaxed)).unwrap_or(0)
    }
    /// Reset per-cycle counters only (for fair competition).
    /// Cumulative counters (upload/download) are NEVER reset — they track lifetime totals.
    pub fn reset_cycle_counters(&self) {
        for entry in self.cycle_upload.iter() {
            entry.value().store(0, Ordering::Relaxed);
        }
        for entry in self.cycle_download.iter() {
            entry.value().store(0, Ordering::Relaxed);
        }
    }

    /// Reset ALL per-cycle counters and set cumulative to current cycle values.
    /// Called after new IPs are added so all IPs start with fresh cycle values.
    /// Cumulative (Total) is NOT reset — it keeps lifetime data.
    pub fn reset_for_new_cycle(&self) {
        for entry in self.cycle_upload.iter() {
            entry.value().store(0, Ordering::Relaxed);
        }
        for entry in self.cycle_download.iter() {
            entry.value().store(0, Ordering::Relaxed);
        }
    }
}

/// Events emitted by the find_ip proxy for the TUI dashboard.
#[derive(Debug, Clone)]
pub enum FindIpEvent {
    IpAdded {
        ip: IpAddr,
        score: u8,
    },
}

pub type FindIpEventSender = mpsc::UnboundedSender<FindIpEvent>;

pub fn new_ip_byte_counters() -> IpByteCounters {
    Arc::new(IpByteCountersInner::new())
}

/// Run the find_ip live proxy.
///
/// Maintains up to `MAX_IP` concurrent outbound connections to `domain:443`
/// through different IPs from the candidate pool.  VPN traffic is distributed
/// across the pool using round-robin.  Dead IPs (0 bytes in a cycle) are
/// replaced with top-scored candidates from the IP scanner.
#[allow(clippy::too_many_arguments)]
pub async fn run_find_ip_proxy(
    cfg: Arc<Config>,
    selected_sni: String,
    candidate_ips: Vec<IpAddr>,
    pool: Arc<RwLock<IpPool>>,
    byte_counters: IpByteCounters,
    event_tx: Option<ProxyEventSender>,
    find_ip_event_tx: Option<FindIpEventSender>,
    stats: Arc<std::sync::Mutex<CycleManagerStats>>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, sni = %selected_sni, "find_ip: listening");

    let max_ip = cfg.MAX_IP;
    let cycle_secs = cfg.IP_TEST_TIMEOUT_SECS;
    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    // Pre-clone for the cycle manager (async move captures by move).
    let cycle_cfg = cfg.clone();
    let cycle_pool = pool.clone();
    let cycle_counters = byte_counters.clone();
    let cycle_candidates = candidate_ips.clone();
    let cycle_find_tx = find_ip_event_tx.clone();
    let cycle_stats = stats.clone();
    tokio::spawn(async move {
        find_ip_cycle_manager(CycleManagerConfig {
            cfg: cycle_cfg,
            candidate_ips: cycle_candidates,
            pool: cycle_pool,
            byte_counters: cycle_counters,
            find_ip_event_tx: cycle_find_tx,
            scan_sni,
            scan_timeout,
            max_ip,
            cycle_secs,
            stats: cycle_stats,
        })
        .await;
    });

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "find_ip: accept failed");
                continue;
            }
        };
        debug!(%peer, "find_ip: accepted");

        // Round-robin: pick the next IP from the pool.
        let connect_ip = {
            let mut p = pool.write().unwrap();
            match p.next_ip() {
                Some(ip) => ip,
                None => {
                    warn!("find_ip: no active IPs in pool; dropping connection");
                    continue;
                }
            }
        };

        let connect_addr = SocketAddr::new(connect_ip, CONNECT_PORT);
        let src_port = peer.port();
        let ev_tx = event_tx.clone();

        emit(&ev_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

        byte_counters.inc_connection(&connect_ip);
        let upload_counter = byte_counters.get_upload(&connect_ip);
        let download_counter = byte_counters.get_download(&connect_ip);
        let cycle_upload = byte_counters.cycle_upload.entry(connect_ip).or_insert_with(|| Arc::new(AtomicU64::new(0))).clone();
        let cycle_download = byte_counters.cycle_download.entry(connect_ip).or_insert_with(|| Arc::new(AtomicU64::new(0))).clone();

        let relay_max_lifetime = configured_relay_max_lifetime(&cfg);

        tokio::spawn(async move {
            let outgoing = match TcpStream::connect(connect_addr).await {
                Ok(s) => s,
                Err(e) => {
                    emit(
                        &ev_tx,
                        ProxyEvent::ConnectionError {
                            src_port,
                            error: e.to_string(),
                        },
                    );
                    return;
                }
            };

            emit(
                &ev_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::FakeDataAcked,
                },
            );

            let (inc_rd, inc_wr) = incoming.into_split();
            let (out_rd, out_wr) = outgoing.into_split();

            let mut c2s_task = tokio::spawn(copy_counting_dual(inc_rd, out_wr, upload_counter.clone(), cycle_upload));
            let mut s2c_task = tokio::spawn(copy_counting_dual(out_rd, inc_wr, download_counter.clone(), cycle_download));

            let ticker = ev_tx.as_ref().map(|tx| {
                let tx = tx.clone();
                let u = upload_counter.clone();
                let d = download_counter.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_millis(500));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    interval.tick().await;
                    loop {
                        interval.tick().await;
                        let _ = tx.send(ProxyEvent::RelayProgress {
                            src_port,
                            c2s_bytes: u.load(Ordering::Relaxed),
                            s2c_bytes: d.load(Ordering::Relaxed),
                        });
                    }
                })
            });

            let result = if let Some(max_lifetime) = relay_max_lifetime {
                let mut c2s_done: Option<u64> = None;
                let mut s2c_done: Option<u64> = None;
                let deadline = tokio::time::sleep(max_lifetime);
                tokio::pin!(deadline);

                loop {
                    tokio::select! {
                        _ = &mut deadline => {
                            if c2s_done.is_none() { c2s_task.abort(); }
                            if s2c_done.is_none() { s2c_task.abort(); }
                            break RelayResult {
                                c2s_bytes: c2s_done.unwrap_or_else(|| upload_counter.load(Ordering::Relaxed)),
                                s2c_bytes: s2c_done.unwrap_or_else(|| download_counter.load(Ordering::Relaxed)),
                                reason: RelayEndReason::MaxLifetime,
                            };
                        }
                        r = &mut c2s_task, if c2s_done.is_none() => {
                            c2s_done = Some(r.unwrap_or(0));
                            if let (Some(c), Some(s)) = (c2s_done, s2c_done) {
                                break RelayResult { c2s_bytes: c, s2c_bytes: s, reason: RelayEndReason::Completed };
                            }
                        }
                        r = &mut s2c_task, if s2c_done.is_none() => {
                            s2c_done = Some(r.unwrap_or(0));
                            if let (Some(c), Some(s)) = (c2s_done, s2c_done) {
                                break RelayResult { c2s_bytes: c, s2c_bytes: s, reason: RelayEndReason::Completed };
                            }
                        }
                    }
                }
            } else {
                let (c, s) = tokio::join!(c2s_task, s2c_task);
                RelayResult {
                    c2s_bytes: c.unwrap_or(0),
                    s2c_bytes: s.unwrap_or(0),
                    reason: RelayEndReason::Completed,
                }
            };

            if let Some(t) = ticker { t.abort(); }

            emit(
                &ev_tx,
                ProxyEvent::RelayFinished {
                    src_port,
                    c2s_bytes: result.c2s_bytes,
                    s2c_bytes: result.s2c_bytes,
                    reason: result.reason,
                },
            );
        });
    }
}

/// Configuration for the find_ip cycle manager.
struct CycleManagerConfig {
    cfg: Arc<Config>,
    candidate_ips: Vec<IpAddr>,
    pool: Arc<RwLock<IpPool>>,
    byte_counters: IpByteCounters,
    find_ip_event_tx: Option<FindIpEventSender>,
    scan_sni: Arc<str>,
    scan_timeout: Duration,
    max_ip: usize,
    cycle_secs: u64,
    stats: Arc<std::sync::Mutex<CycleManagerStats>>,
}

/// Stats tracked by the cycle manager for display.
pub struct CycleManagerStats {
    pub total_scanned: u64,
    pub total_successful: u64,
    pub total_removed: u64,
}

impl CycleManagerStats {
    pub fn new() -> Self {
        Self { total_scanned: 0, total_successful: 0, total_removed: 0 }
    }
}

impl Default for CycleManagerStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Background cycle manager for find_ip mode.
///
/// Every `cycle_secs` seconds, evaluates bytes per IP, removes dead IPs,
/// replaces them immediately from pre-scanned candidates, and periodically
/// runs a full scan to refresh the candidate list.
async fn find_ip_cycle_manager(cmc: CycleManagerConfig) {
    use crate::ip_scanner::scan_ip_list;

    let mut cycle_num: u64 = 0;
    let cycle_interval = Duration::from_secs(cmc.cycle_secs);

    // Pre-scanned candidates (sorted by score desc).
    // Start with empty list — will be populated by the first scan in the loop.
    let mut pre_scanned: Vec<IpProbeEntry> = Vec::new();

    loop {
        tokio::time::sleep(cycle_interval).await;

        if cmc.pool.read().unwrap().is_fixed() {
            debug!("find_ip: pool is fixed; cycle manager stopping");
            break;
        }

        cycle_num += 1;
        let mut dead_ips: Vec<IpAddr> = Vec::new();

        // First: evaluate using TOTAL lifetime bytes (not per-cycle).
        let active = cmc.pool.read().unwrap().active_ips().to_vec();
        let mut ip_stats: Vec<(IpAddr, u64, u64, u64)> = Vec::new();
        for ip in &active {
            let (upload, download) = cmc.byte_counters.total_bytes(ip);
            let conns = cmc.byte_counters.connection_count(ip);
            ip_stats.push((*ip, upload, download, conns));
        }

        // Only start judging after at least one IP has connections.
        let any_connected = ip_stats.iter().any(|(_, _, _, c)| *c > 0);
        if any_connected {
            let drop_count = cmc.cfg.FIND_IP_DROP_COUNT;
            let all_have_total = ip_stats.iter().all(|(_, u, d, _)| *u + *d > 0);

            if all_have_total && drop_count > 0 {
                // All IPs have total bytes — remove the lowest by total.
                let mut sorted = ip_stats.clone();
                sorted.sort_by_key(|(_, u, d, _)| *u + *d);
                let to_remove = drop_count.min(sorted.len());
                for (ip, _, _, _) in sorted.iter().take(to_remove) {
                    dead_ips.push(*ip);
                }
                debug!(count = to_remove, "find_ip: removing lowest-total IPs (all have bytes)");
            } else {
                // Some IPs have 0 total — remove them.
                for (ip, upload, download, _) in &ip_stats {
                    if *upload + *download == 0 {
                        dead_ips.push(*ip);
                    }
                }
            }
        }

        // Remove dead IPs from the pool.
        {
            let mut p = cmc.pool.write().unwrap();
            for ip in &dead_ips {
                p.remove_ip(ip);
                debug!(%ip, "find_ip: removed IP from pool");
            }
            cmc.stats.lock().unwrap().total_removed += dead_ips.len() as u64;
        }

        // Replace dead IPs — use pre_scanned first (fast), then scan if needed.
        let mut replaced_count = 0usize;
        {
            let mut p = cmc.pool.write().unwrap();
            let active_now: Vec<IpAddr> = p.active_ips().to_vec();
            // First: fill from pre_scanned cache.
            pre_scanned.retain(|entry| {
                if p.active_count() >= cmc.max_ip {
                    return true;
                }
                if !active_now.contains(&entry.ip) {
                    p.add_ip(entry.ip);
                    replaced_count += 1;
                    info!(ip = %entry.ip, score = entry.score, "find_ip: added IP from cache");
                    if let Some(ref tx) = cmc.find_ip_event_tx {
                        let _ = tx.send(FindIpEvent::IpAdded { ip: entry.ip, score: entry.score });
                    }
                    false
                } else {
                    true
                }
            });
        }

        // If pool still needs IPs, run scan incrementally.
        if cmc.pool.read().unwrap().active_count() < cmc.max_ip {
            // Take a random subset of candidates for faster scanning.
            let mut candidates = cmc.candidate_ips.clone();
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            candidates.sort_by_key(|ip| {
                let mut h = DefaultHasher::new();
                ip.hash(&mut h);
                seed.wrapping_add(h.finish())
            });
            let scan_limit = (cmc.max_ip * 20).min(candidates.len());
            candidates.truncate(scan_limit);

            // Run scan with progress channel — add IPs incrementally.
            let (scan_tx, mut scan_rx) = mpsc::unbounded_channel::<IpScanEvent>();
            let scan_cfg = cmc.cfg.clone();
            let scan_sni = cmc.scan_sni.clone();
            let scan_timeout = cmc.scan_timeout;
            let scan_candidates = candidates.clone();

            let scan_handle = tokio::spawn(async move {
                scan_ip_list(scan_candidates, scan_sni, scan_timeout, scan_cfg, Some(scan_tx)).await
            });

            // Process results incrementally — every 2 seconds check for new results.
            let mut scan_done = false;
            let mut all_scan_results: Vec<IpProbeEntry> = Vec::new();
            let mut tcp_tested: usize = 0;
            while !scan_done {
                // Check if scan is done.
                if scan_handle.is_finished() {
                    scan_done = true;
                    // Drain remaining results.
                    while let Ok(event) = scan_rx.try_recv() {
                        match event {
                            IpScanEvent::TcpDone { tcp_tested: t } => { tcp_tested = t; }
                            IpScanEvent::ProbeComplete(entry) => { all_scan_results.push(entry); }
                        }
                    }
                } else {
                    // Wait a bit for new results.
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                    while let Ok(event) = scan_rx.try_recv() {
                        match event {
                            IpScanEvent::TcpDone { tcp_tested: t } => { tcp_tested = t; }
                            IpScanEvent::ProbeComplete(entry) => { all_scan_results.push(entry); }
                        }
                    }
                }

                // Update stats (cumulative across cycles).
                {
                    let mut stats = cmc.stats.lock().unwrap();
                    stats.total_scanned += tcp_tested as u64;
                    stats.total_successful += all_scan_results.iter().filter(|e| e.score > 0).count() as u64;
                }

                // Add best IPs to pool immediately.
                if cmc.pool.read().unwrap().is_fixed() {
                    debug!("find_ip: pool fixed during scan; stopping");
                    scan_handle.abort();
                    break;
                }

                {
                    let mut p = cmc.pool.write().unwrap();
                    let active_now: Vec<IpAddr> = p.active_ips().to_vec();
                    for entry in &all_scan_results {
                        if p.active_count() >= cmc.max_ip {
                            // Cache remaining for later.
                            if !active_now.contains(&entry.ip) && !pre_scanned.iter().any(|e| e.ip == entry.ip) {
                                pre_scanned.push(entry.clone());
                            }
                            continue;
                        }
                        if !active_now.contains(&entry.ip) && !pre_scanned.iter().any(|e| e.ip == entry.ip) {
                            p.add_ip(entry.ip);
                            replaced_count += 1;
                            info!(ip = %entry.ip, score = entry.score, "find_ip: added replacement IP from scan");
                            if let Some(ref tx) = cmc.find_ip_event_tx {
                                let _ = tx.send(FindIpEvent::IpAdded { ip: entry.ip, score: entry.score });
                            }
                        } else if !active_now.contains(&entry.ip) {
                            pre_scanned.push(entry.clone());
                        }
                    }
                    pre_scanned.sort_by_key(|b| std::cmp::Reverse(b.score));
                }

                // If pool is full, stop scanning.
                if cmc.pool.read().unwrap().active_count() >= cmc.max_ip {
                    scan_handle.abort();
                    break;
                }
            }
        }

        // Reset per-cycle counters AFTER new IPs are added — fair competition.
        // Cumulative (Total) is NOT reset — it tracks lifetime data.
        cmc.byte_counters.reset_cycle_counters();
        cmc.pool.write().unwrap().update_cycle_counts(cmc.cycle_secs);

        info!(
            cycle = cycle_num,
            active = cmc.pool.read().unwrap().active_count(),
            dead = dead_ips.len(),
            replaced = replaced_count,
            pre_scanned = pre_scanned.len(),
            "find_ip: cycle complete"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn relay_without_max_lifetime_completes_on_eof() {
        let (mut client, incoming) = tcp_pair().await;
        let (mut upstream, outgoing) = tcp_pair().await;

        let relay = tokio::spawn(counting_relay(incoming, outgoing, &None, 1234, None));

        client.write_all(b"ping").await.unwrap();
        let mut upstream_buf = [0u8; 4];
        upstream.read_exact(&mut upstream_buf).await.unwrap();
        assert_eq!(&upstream_buf, b"ping");

        upstream.write_all(b"pong").await.unwrap();
        let mut client_buf = [0u8; 4];
        client.read_exact(&mut client_buf).await.unwrap();
        assert_eq!(&client_buf, b"pong");

        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.reason, RelayEndReason::Completed);
        assert_eq!(result.c2s_bytes, 4);
        assert_eq!(result.s2c_bytes, 4);
    }

    #[tokio::test]
    async fn relay_with_max_lifetime_rotates_open_connection() {
        let (_client, incoming) = tcp_pair().await;
        let (_upstream, outgoing) = tcp_pair().await;

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            counting_relay(
                incoming,
                outgoing,
                &None,
                1234,
                Some(Duration::from_millis(25)),
            ),
        )
        .await
        .unwrap();

        assert_eq!(result.reason, RelayEndReason::MaxLifetime);
        assert_eq!(result.c2s_bytes, 0);
        assert_eq!(result.s2c_bytes, 0);
    }

    #[tokio::test]
    async fn relay_rotation_preserves_bytes_copied_before_expiry() {
        let (mut client, incoming) = tcp_pair().await;
        let (mut upstream, outgoing) = tcp_pair().await;

        let relay = tokio::spawn(counting_relay(
            incoming,
            outgoing,
            &None,
            1234,
            Some(Duration::from_millis(50)),
        ));

        client.write_all(b"hello").await.unwrap();
        let mut upstream_buf = [0u8; 5];
        upstream.read_exact(&mut upstream_buf).await.unwrap();
        assert_eq!(&upstream_buf, b"hello");

        let result = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.reason, RelayEndReason::MaxLifetime);
        assert_eq!(result.c2s_bytes, 5);
        assert_eq!(result.s2c_bytes, 0);
    }

    #[test]
    fn combo_tls_frag_methods_segment_first_client_hello() {
        assert!(method_segments_first_client_hello("wrong_seq_tls_frag"));
        assert!(method_segments_first_client_hello("wrong_md5_tls_frag"));
        assert!(!method_segments_first_client_hello(
            "wrong_seq_tls_record_frag"
        ));
        assert!(!method_segments_first_client_hello("tls_record_frag"));
        assert!(!method_segments_first_client_hello("tls_frag"));
    }
}
