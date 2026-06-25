use super::config::RemoteConfig;
use super::groups::{SharedConnection, TunnelGroups};
use crate::{cert, common::proto, quic};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use s2n_quic::stream::BidirectionalStream;
use std::{error::Error, net::SocketAddr, sync::Arc};
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

    if config.is_group_http_mode() {
        run_group_http_mode(config).await
    } else {
        run_legacy_tcp_mode(config).await
    }
}

// ---------------------------------------------------------------------------
// Reverst-style: shared HTTP listener + tunnel groups + round-robin clients
// ---------------------------------------------------------------------------

async fn run_group_http_mode(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let groups = config.tunnel_groups.clone().expect("group mode");
    let http_addr = config.http_address.expect("group mode");

    let mut quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    log::info!("QUIC tunnel listener on {}", config.quic_address);
    log::info!("HTTP reverse-proxy listener on {http_addr}");
    log::info!("Tunnel groups: {:?}", groups.group_names());

    let groups_accept = groups.clone();
    tokio::spawn(async move {
        while let Some(conn) = quic_srv.accept().await {
            let groups = groups_accept.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_group_registration(conn, groups).await {
                    log::warn!("Tunnel client session ended: {e}");
                }
            });
        }
    });

    serve_http_proxy(http_addr, groups).await
}

async fn handle_group_registration(
    mut quic_conn: s2n_quic::Connection,
    groups: TunnelGroups,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let peer = quic_conn
        .remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());

    let Some(mut reg_stream) = quic_conn.accept_bidirectional_stream().await? else {
        return Ok(());
    };

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
            let _ = reg_stream
                .send(proto::ProtoCommand::RegisterErr("expected REGISTER".into()).deserialize())
                .await;
            return Err("expected REGISTER".into());
        }
    };

    if let Err(e) = groups.authenticate(&group, authorization.as_deref()) {
        let _ = reg_stream
            .send(proto::ProtoCommand::RegisterErr(e.clone()).deserialize())
            .await;
        return Err(e.into());
    }

    reg_stream
        .send(proto::ProtoCommand::REGISTERED.deserialize())
        .await?;
    // Registration stream done; drop it so only data streams remain in use.
    drop(reg_stream);

    let shared: SharedConnection = Arc::new(Mutex::new(quic_conn));
    groups.register(&group, shared.clone()).await?;
    log::info!("Registered tunnel client from {peer} on group {group}");

    // Stay registered until the process ends or the connection is dropped.
    // Liveness is observed when the HTTP proxy fails to open streams.
    // Do not hold the connection mutex here (proxy needs it for open_bidirectional_stream).
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    {
        groups.unregister(&group, &shared).await;
        Ok(())
    }
}

async fn serve_http_proxy(
    http_addr: SocketAddr,
    groups: TunnelGroups,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind(http_addr).await?;
    log::info!("HTTP proxy accepting connections on {http_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let groups = groups.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let groups = groups.clone();
                async move { proxy_request(req, groups).await }
            });
            if let Err(e) = server_http1::Builder::new().serve_connection(io, svc).await {
                log::debug!("HTTP connection from {peer} ended: {e}");
            }
        });
    }
}

async fn proxy_request(
    req: Request<Incoming>,
    groups: TunnelGroups,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let host = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let host_key = host
        .rsplit_once(':')
        .filter(|(h, p)| p.chars().all(|c| c.is_ascii_digit()) && !h.is_empty())
        .map(|(h, _)| h.to_string())
        .unwrap_or(host);

    let Some(group) = groups.resolve_group(&host_key) else {
        log::debug!("No tunnel group for host {host_key}");
        return Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from_static(b"bad gateway: unknown host")))
            .unwrap());
    };

    let Some(client) = groups.next_client(&group).await else {
        log::debug!("No active clients in group {group}");
        return Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from_static(
                b"bad gateway: no tunnel clients",
            )))
            .unwrap());
    };

    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| std::io::Error::other(e))?
        .to_bytes();
    let outbound = Request::from_parts(parts, Full::new(body_bytes));

    let quic_stream = {
        let mut guard = client.lock().await;
        guard
            .open_bidirectional_stream()
            .await
            .map_err(|e| std::io::Error::other(e))?
    };

    let io = TokioIo::new(quic_stream);
    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .map_err(|e| std::io::Error::other(e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let response = sender
        .send_request(outbound)
        .await
        .map_err(|e| std::io::Error::other(e))?;
    let (res_parts, res_body) = response.into_parts();
    let res_bytes = res_body
        .collect()
        .await
        .map_err(|e| std::io::Error::other(e))?
        .to_bytes();

    log::debug!(
        "Proxied to group {group}: {} ({} bytes)",
        res_parts.status,
        res_bytes.len()
    );

    Ok(Response::from_parts(res_parts, Full::new(res_bytes)))
}

// ---------------------------------------------------------------------------
// Legacy mode: one TCP port per local client (original sirang behaviour)
// ---------------------------------------------------------------------------

async fn run_legacy_tcp_mode(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv = setup_quic_server(&config).await?;
    let (global_shutdown_tx, mut global_shutdown_rx) = setup_global_shutdown();

    handle_connections(&mut quic_srv, config, global_shutdown_tx, &mut global_shutdown_rx).await
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
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    loop {
        let quic_conn = tokio::select! {
            Some(qc) = quic_srv.accept() => qc,
            _ = global_shutdown_rx.recv() => {
                log::info!("Global shutdown signal received, exiting...");
                return Ok(());
            }
        };

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
