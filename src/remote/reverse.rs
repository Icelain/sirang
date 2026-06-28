use super::config::RemoteConfig;
use super::groups::{SharedConnection, TunnelGroups};
use super::metrics::{self, Metrics};
use crate::{cert, common::proto, quic};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::header::{HeaderValue, CONNECTION, HOST, VIA};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use s2n_quic::stream::BidirectionalStream;
use std::{error::Error, net::SocketAddr, sync::Arc, time::Instant};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{self, channel, Sender},
        Mutex,
    },
};

#[derive(Debug)]
enum CloseAction {
    CloseProcess,
    CloseStream,
}

pub async fn reverse_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    cert::serve_cert(config.cert_listen_addr(), config.tls_cert.clone()).await?;

    let metrics = Metrics::new();
    if let Some(mgmt) = config.management_address {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve_management(mgmt, m).await {
                log::error!("Management server error: {e}");
            }
        });
    }

    if config.is_group_http_mode() {
        run_group_http_mode(config, metrics).await
    } else {
        run_legacy_tcp_mode(config, metrics).await
    }
}

// ---------------------------------------------------------------------------
// Reverst-style: shared HTTP listener + tunnel groups + round-robin clients
// ---------------------------------------------------------------------------

async fn run_group_http_mode(
    config: RemoteConfig,
    metrics: Metrics,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let groups = config.tunnel_groups.clone().expect("group mode");
    let http_addr = config.http_address.expect("group mode");

    let mut quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    log::info!("QUIC tunnel listener on {}", config.quic_address);
    log::info!("HTTP reverse-proxy listener on {http_addr}");
    log::info!("Tunnel groups: {:?}", groups.group_names());

    let groups_accept = groups.clone();
    let metrics_accept = metrics.clone();
    let connect_password = config.connect_password.clone();
    tokio::spawn(async move {
        while let Some(conn) = quic_srv.accept().await {
            metrics_accept.quic_accepted();
            let groups = groups_accept.clone();
            let metrics = metrics_accept.clone();
            let connect_password = connect_password.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_group_registration(conn, groups, metrics, connect_password).await
                {
                    log::warn!("Tunnel client session ended: {e}");
                }
            });
        }
    });

    serve_http_proxy(http_addr, groups, metrics).await
}

/// Challenge the local client for a connect password when configured.
async fn challenge_connect_password(
    stream: &mut BidirectionalStream,
    expected: &str,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    stream
        .send(proto::ProtoCommand::AuthRequired.deserialize())
        .await?;
    let data = stream
        .receive()
        .await?
        .ok_or("client closed during password challenge")?;
    match proto::ProtoCommand::serialize(data) {
        Some(proto::ProtoCommand::Auth(provided))
            if proto::passwords_equal(expected, &provided) =>
        {
            stream
                .send(proto::ProtoCommand::AuthOk.deserialize())
                .await?;
            log::debug!("Connect password accepted");
            Ok(())
        }
        Some(proto::ProtoCommand::Auth(_)) => {
            let _ = stream
                .send(proto::ProtoCommand::AuthErr("invalid password".into()).deserialize())
                .await;
            Err("invalid connect password".into())
        }
        Some(proto::ProtoCommand::REGISTER { .. }) => {
            let _ = stream
                .send(
                    proto::ProtoCommand::AuthErr("password required before REGISTER".into())
                        .deserialize(),
                )
                .await;
            Err("password required".into())
        }
        _ => {
            let _ = stream
                .send(proto::ProtoCommand::AuthErr("expected AUTH".into()).deserialize())
                .await;
            Err("expected AUTH response".into())
        }
    }
}

async fn handle_group_registration(
    mut quic_conn: s2n_quic::Connection,
    groups: TunnelGroups,
    metrics: Metrics,
    connect_password: Option<String>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let peer = quic_conn
        .remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());

    let Some(mut reg_stream) = quic_conn.accept_bidirectional_stream().await? else {
        return Ok(());
    };

    if let Some(ref password) = connect_password {
        if let Err(e) = challenge_connect_password(&mut reg_stream, password).await {
            metrics.registration("_", "unauthorized");
            return Err(e);
        }
    }

    let data = match reg_stream.receive().await? {
        Some(d) => d,
        None => return Ok(()),
    };

    let cmd = proto::ProtoCommand::serialize(data).ok_or("invalid registration command")?;
    let (group, authorization) = match cmd {
        proto::ProtoCommand::REGISTER {
            group,
            authorization,
        } => (group, authorization),
        _ => {
            metrics.registration("_", "error");
            let _ = reg_stream
                .send(proto::ProtoCommand::RegisterErr("expected REGISTER".into()).deserialize())
                .await;
            return Err("expected REGISTER".into());
        }
    };

    if let Err(e) = groups.authenticate(&group, authorization.as_deref()) {
        let result = if e.contains("unknown") {
            "not_found"
        } else {
            "unauthorized"
        };
        metrics.registration(&group, result);
        let _ = reg_stream
            .send(proto::ProtoCommand::RegisterErr(e.clone()).deserialize())
            .await;
        return Err(e.into());
    }

    reg_stream
        .send(proto::ProtoCommand::REGISTERED.deserialize())
        .await?;
    drop(reg_stream);

    let shared: SharedConnection = Arc::new(Mutex::new(quic_conn));
    if let Err(e) = groups.register(&group, shared.clone()).await {
        metrics.registration(&group, "error");
        return Err(e.into());
    }
    metrics.registration(&group, "ok");
    metrics.client_registered(&group);
    log::info!("Registered tunnel client from {peer} on group {group}");

    // Park until process exit; connection liveness observed on proxy stream opens.
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    {
        groups.unregister(&group, &shared).await;
        metrics.client_unregistered(&group);
        Ok(())
    }
}

async fn serve_http_proxy(
    http_addr: SocketAddr,
    groups: TunnelGroups,
    metrics: Metrics,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind(http_addr).await?;
    log::info!("HTTP proxy accepting connections on {http_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let groups = groups.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let groups = groups.clone();
                let metrics = metrics.clone();
                async move { proxy_request(req, groups, metrics).await }
            });
            // Preserve header case and use proper HTTP/1 framing on the public edge.
            if let Err(e) = server_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(false)
                .serve_connection(io, svc)
                .await
            {
                log::debug!("HTTP connection from {peer} ended: {e}");
            }
        });
    }
}

/// Proxy an inbound HTTP/1 request onto a tunnel client using framed HTTP/1 over QUIC.
async fn proxy_request(
    req: Request<Incoming>,
    groups: TunnelGroups,
    metrics: Metrics,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let start = Instant::now();

    let host_header = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let host_key = strip_port(&host_header);

    let Some(group) = groups.resolve_group(&host_key) else {
        log::debug!(target: "sirang::proxy", "unknown host host={host_key}");
        metrics.proxy_request(&host_key, "_", 502, start.elapsed());
        return Ok(framed_error(
            StatusCode::BAD_GATEWAY,
            b"bad gateway: unknown host",
        ));
    };

    let Some(client) = groups.next_client(&group).await else {
        log::debug!(target: "sirang::proxy", "no clients group={group} host={host_key}");
        metrics.proxy_request(&host_key, &group, 502, start.elapsed());
        return Ok(framed_error(
            StatusCode::BAD_GATEWAY,
            b"bad gateway: no tunnel clients",
        ));
    };

    let method = req.method().clone();
    let uri = req.uri().clone();
    let (mut parts, body) = req.into_parts();

    // Collect body so we can set a definitive Content-Length (correct HTTP framing).
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            metrics.proxy_error();
            return Err(std::io::Error::other(e));
        }
    };

    // Strip hop-by-hop headers before framing onto the tunnel.
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.insert(
        VIA,
        HeaderValue::from_static("1.1 sirang"),
    );
    // Ensure Content-Length matches framed body.
    parts.headers.remove(hyper::header::TRANSFER_ENCODING);
    parts.headers.insert(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_bytes.len().to_string()).unwrap(),
    );

    let outbound = Request::from_parts(parts, Full::new(body_bytes));

    let quic_stream = {
        let mut guard = client.lock().await;
        match guard.open_bidirectional_stream().await {
            Ok(s) => s,
            Err(e) => {
                log::warn!(target: "sirang::proxy", "open stream failed group={group}: {e}");
                metrics.proxy_error();
                metrics.proxy_request(&host_key, &group, 502, start.elapsed());
                return Ok(framed_error(
                    StatusCode::BAD_GATEWAY,
                    b"bad gateway: tunnel stream error",
                ));
            }
        }
    };

    let io = TokioIo::new(quic_stream);
    let (mut sender, conn) = match client_http1::Builder::new()
        .preserve_header_case(true)
        .handshake(io)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            log::warn!(target: "sirang::proxy", "HTTP framing handshake failed: {e}");
            metrics.proxy_error();
            metrics.proxy_request(&host_key, &group, 502, start.elapsed());
            return Ok(framed_error(
                StatusCode::BAD_GATEWAY,
                b"bad gateway: framing error",
            ));
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let response = match sender.send_request(outbound).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!(target: "sirang::proxy", "send_request failed: {e}");
            metrics.proxy_error();
            metrics.proxy_request(&host_key, &group, 502, start.elapsed());
            return Ok(framed_error(
                StatusCode::BAD_GATEWAY,
                b"bad gateway: upstream error",
            ));
        }
    };

    let status = response.status();
    let (mut res_parts, res_body) = response.into_parts();
    let res_bytes = match res_body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            metrics.proxy_error();
            return Err(std::io::Error::other(e));
        }
    };

    strip_hop_by_hop(&mut res_parts.headers);
    res_parts.headers.remove(hyper::header::TRANSFER_ENCODING);
    res_parts.headers.insert(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&res_bytes.len().to_string()).unwrap(),
    );
    if let Ok(v) = HeaderValue::from_str("1.1 sirang") {
        res_parts.headers.append(VIA, v);
    }

    let elapsed = start.elapsed();
    metrics.proxy_request(&host_key, &group, status.as_u16(), elapsed);
    log::info!(
        target: "sirang::proxy",
        "{method} {uri} host={host_key} group={group} status={} bytes={} latency_ms={:.2}",
        status.as_u16(),
        res_bytes.len(),
        elapsed.as_secs_f64() * 1000.0
    );

    Ok(Response::from_parts(res_parts, Full::new(res_bytes)))
}

fn framed_error(status: StatusCode, body: &'static [u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(hyper::header::CONTENT_LENGTH, body.len())
        .header(CONNECTION, "close")
        .header(VIA, "1.1 sirang")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap()
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    const HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ];
    // Remove headers listed in Connection and known hop-by-hop names.
    let mut extra = Vec::new();
    if let Some(conn) = headers.get(CONNECTION).and_then(|v| v.to_str().ok()) {
        for name in conn.split(',') {
            let name = name.trim();
            if !name.is_empty() {
                extra.push(name.to_string());
            }
        }
    }
    for name in HOP {
        headers.remove(*name);
    }
    for name in extra {
        headers.remove(name);
    }
}

fn strip_port(host: &str) -> String {
    if let Some((h, p)) = host.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() && !host.starts_with('[') {
            return h.to_string();
        }
    }
    host.to_string()
}

// ---------------------------------------------------------------------------
// Legacy mode: one TCP port per local client (original sirang behaviour)
// ---------------------------------------------------------------------------

async fn run_legacy_tcp_mode(
    config: RemoteConfig,
    metrics: Metrics,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv = setup_quic_server(&config).await?;
    let (global_shutdown_tx, mut global_shutdown_rx) = setup_global_shutdown();

    handle_connections(
        &mut quic_srv,
        config,
        global_shutdown_tx,
        &mut global_shutdown_rx,
        metrics,
    )
    .await
}

async fn setup_quic_server(
    config: &RemoteConfig,
) -> Result<s2n_quic::Server, Box<dyn Error + Send + Sync + 'static>> {
    let quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    log::info!("Quic Server started on: {}", config.quic_address);
    log::info!(
        "Preferred Tcp listen address: {}",
        config.tcp_reverse_address.unwrap()
    );

    Ok(quic_srv)
}

fn setup_global_shutdown() -> (Sender<()>, mpsc::Receiver<()>) {
    let (global_shutdown_tx, global_shutdown_rx) = channel::<()>(1);
    let global_shutdown_tx_clone = global_shutdown_tx.clone();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            log::info!("Received Ctrl-C signal, initiating shutdown...");
            let _ = global_shutdown_tx_clone.send(()).await;
        }
    });

    (global_shutdown_tx, global_shutdown_rx)
}

async fn handle_connections(
    quic_srv: &mut s2n_quic::Server,
    config: RemoteConfig,
    global_shutdown_tx: Sender<()>,
    global_shutdown_rx: &mut mpsc::Receiver<()>,
    metrics: Metrics,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    loop {
        let quic_conn = tokio::select! {
            Some(qc) = quic_srv.accept() => qc,
            _ = global_shutdown_rx.recv() => {
                log::info!("Global shutdown signal received, exiting...");
                return Ok(());
            }
        };
        metrics.quic_accepted();

        let cfg = config.clone();
        let gtx = global_shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client_connection(quic_conn, cfg, gtx).await {
                log::warn!("Client session ended with error: {e}");
            }
        });
    }
}

async fn handle_client_connection(
    mut quic_conn: s2n_quic::Connection,
    config: RemoteConfig,
    global_shutdown_tx: Sender<()>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    if let Ok(client_address) = quic_conn.remote_addr() {
        log::info!("Local client connected from {client_address}");
    }

    let Some(mut command_stream) = quic_conn.accept_bidirectional_stream().await? else {
        return Ok(());
    };

    if let Some(ref password) = config.connect_password {
        challenge_connect_password(&mut command_stream, password).await?;
    }

    let (tcp_listener, bound_addr) = setup_tcp_listener(&config).await?;
    send_connection_handshake(&mut command_stream, bound_addr).await?;

    let (close_tcpwait_sender, mut close_tcpwait_receiver) = mpsc::channel::<CloseAction>(1);

    spawn_command_stream_handler(command_stream, close_tcpwait_sender, global_shutdown_tx);

    handle_tcp_connections(
        tcp_listener,
        &mut quic_conn,
        config.buffer_size,
        &mut close_tcpwait_receiver,
    )
    .await?;

    if let Ok(client_address) = quic_conn.remote_addr() {
        log::debug!("Local client disconnected: {client_address}");
    }

    Ok(())
}

async fn setup_tcp_listener(
    config: &RemoteConfig,
) -> Result<(TcpListener, SocketAddr), Box<dyn Error + Send + Sync + 'static>> {
    let preferred = config.tcp_reverse_address.unwrap();
    match TcpListener::bind(preferred).await {
        Ok(listener) => {
            let addr = listener.local_addr()?;
            log::info!("Tcp server for client listening on: {addr}");
            Ok((listener, addr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(preferred.ip(), 0);
            let listener = TcpListener::bind(fallback).await.map_err(|e2| {
                log::warn!("Tcp Listener could not be created on fallback port: {e2}");
                Box::new(e2) as Box<dyn Error + Send + Sync + 'static>
            })?;
            let addr = listener.local_addr()?;
            log::info!(
                "Preferred address {preferred} in use; Tcp server for client listening on: {addr}"
            );
            Ok((listener, addr))
        }
        Err(e) => {
            log::warn!("Tcp Listener could not be created: {e}");
            Err(Box::new(e))
        }
    }
}

async fn send_connection_handshake(
    command_stream: &mut BidirectionalStream,
    bound_addr: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let connected_msg = proto::ProtoCommand::CONNECTED(bound_addr).deserialize();
    command_stream.send(connected_msg).await.map_err(|e| {
        log::warn!(
            "Error while sending connect handshake message to local reverse tunnel instance: {e}"
        );
        Box::new(e) as Box<dyn Error + Send + Sync + 'static>
    })
}

async fn handle_tcp_connections(
    tcp_listener: TcpListener,
    quic_conn: &mut s2n_quic::Connection,
    buffer_size: usize,
    close_tcpwait_receiver: &mut mpsc::Receiver<CloseAction>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    loop {
        let (tcp_stream, tcp_addr) = tokio::select! {
            Ok(res) = tcp_listener.accept() => res,
            Some(close_action) = close_tcpwait_receiver.recv() => {
                match close_action {
                    CloseAction::CloseProcess | CloseAction::CloseStream => {
                        log::debug!("Client session closing TCP accept loop");
                        return Ok(());
                    }
                }
            },
        };

        log::info!("Stream received from {tcp_addr}");
        spawn_stream_handler(quic_conn, tcp_stream, buffer_size).await?;
    }
}

async fn spawn_stream_handler(
    quic_conn: &mut s2n_quic::Connection,
    tcp_stream: TcpStream,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let quic_data_stream = quic_conn.open_bidirectional_stream().await.map_err(|e| {
        log::warn!(
            "Unable to create bidirectional quic stream with local reverse tunnel instance: {e}"
        );
        Box::new(e) as Box<dyn Error + Send + Sync + 'static>
    })?;

    tokio::spawn(handle_stream_copy(
        tcp_stream,
        quic_data_stream,
        buffer_size,
    ));
    Ok(())
}

async fn handle_stream_copy(
    mut tcp_stream: TcpStream,
    mut quic_stream: BidirectionalStream,
    buffer_size: usize,
) {
    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
        &mut tcp_stream,
        &mut quic_stream,
        buffer_size,
        buffer_size,
    )
    .await
    {
        log::warn!("Error during bidirectional copy: {e}");
    }
}

fn spawn_command_stream_handler(
    command_stream: BidirectionalStream,
    close_tcpwait_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    tokio::spawn(handle_command_stream(
        command_stream,
        close_tcpwait_sender,
        global_shutdown_tx,
    ));
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_tcpwait_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    let (receiver, sender) = command_stream.split();
    let sender_arc = Arc::new(Mutex::new(sender));

    spawn_ctrl_c_handler(
        sender_arc.clone(),
        close_tcpwait_sender.clone(),
        global_shutdown_tx,
    );

    handle_command_receiver(receiver, sender_arc, close_tcpwait_sender).await;
}

fn spawn_ctrl_c_handler(
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let mut guard = sender_arc.lock().await;
            let _ = guard.send(proto::ProtoCommand::CLOSED.deserialize()).await;
            let _ = guard.flush().await;
            drop(guard);

            let _ = close_tcpwait_sender.send(CloseAction::CloseProcess).await;
            let _ = global_shutdown_tx.send(()).await;
        }
    });
}

async fn handle_command_receiver(
    mut receiver: s2n_quic::stream::ReceiveStream,
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
) {
    while let Ok(Some(cmd_data)) = receiver.receive().await {
        log::debug!("Received command from client");

        let cmd = match proto::ProtoCommand::serialize(cmd_data) {
            Some(cmd) => cmd,
            None => {
                log::warn!("Received invalid command data");
                continue;
            }
        };

        if let proto::ProtoCommand::CLOSED = cmd {
            log::debug!("Local tunnel instance has closed the connection");
            send_ack_and_close(sender_arc, close_tcpwait_sender.clone()).await;
            break;
        } else {
            log::debug!("Received unhandled command");
        }
    }

    let _ = close_tcpwait_sender.send(CloseAction::CloseStream).await;
}

async fn send_ack_and_close(
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
) {
    let mut guard = sender_arc.lock().await;
    if let Err(e) = guard.send(proto::ProtoCommand::ACK.deserialize()).await {
        log::warn!("Failed to send ACK: {e}");
    }
    drop(guard);

    if let Err(e) = close_tcpwait_sender.send(CloseAction::CloseStream).await {
        log::warn!("Failed to send CloseStream action: {e}");
    }
}
