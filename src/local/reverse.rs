use super::config::LocalConfig;
use crate::{
    cert,
    common::proto::{self, ProtoCommand},
    errors::GenericError,
    quic,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use s2n_quic::stream::BidirectionalStream;
use std::error::Error;
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
};

pub async fn reverse_local(
    mut config: LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    ensure_tls_cert(&mut config).await?;
    let mut quic_client = setup_quic_connection(&config).await?;

    let group_mode = config.tunnel_group.is_some();

    if group_mode {
        register_with_group(&mut quic_client, &config).await?;
        log::info!(
            "Registered on tunnel group {:?} at {} ({}); proxying HTTP to {}",
            config.tunnel_group,
            config.remote_host,
            config.remote_quic_server_addr,
            config.local_tcp_server_addr
        );
        // Always HTTP-proxy in group mode (reverst parity).
        run_stream_loop(quic_client, config.local_tcp_server_addr, true, config.buffer_size).await
    } else {
        let mut command_stream = quic_client.open_bidirectional_stream().await?;
        let remote_tcp_address = perform_handshake(&mut command_stream).await?;
        log::info!(
            "Access this tunnel at {} (via remote {})",
            remote_tcp_address,
            config.remote_host
        );
        if config.http_mode {
            log::info!("HTTP mode enabled: requests over the tunnel are parsed and printed here");
        }

        let (close_channel_sender, mut close_channel_receiver) = channel::<()>(1);
        tokio::spawn(handle_command_stream(command_stream, close_channel_sender));

        loop {
            let server_created_quic_bd_stream = tokio::select! {
                bd_stream = quic_client.accept_bidirectional_stream() => match bd_stream? {
                    Some(s) => s,
                    None => break,
                },
                _ = close_channel_receiver.recv() => break,
            };

            spawn_tunnel_handler(
                server_created_quic_bd_stream,
                config.local_tcp_server_addr,
                config.buffer_size,
                config.http_mode,
            );
        }
        Ok(())
    }
}

async fn run_stream_loop(
    mut quic_client: s2n_quic::connection::Connection,
    local_tcp: SocketAddr,
    http_mode: bool,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    while let Some(stream) = quic_client.accept_bidirectional_stream().await? {
        spawn_tunnel_handler(stream, local_tcp, buffer_size, http_mode);
    }
    Ok(())
}

async fn register_with_group(
    quic_client: &mut s2n_quic::connection::Connection,
    config: &LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let group = config
        .tunnel_group
        .as_ref()
        .ok_or_else(|| GenericError("tunnel group required".into()))?;

    let mut stream = quic_client.open_bidirectional_stream().await?;
    let cmd = ProtoCommand::REGISTER {
        group: group.clone(),
        authorization: config.authorization.clone(),
    };
    stream.send(cmd.deserialize()).await?;

    let resp = match stream.receive().await? {
        Some(d) => d,
        None => {
            return Err(Box::new(GenericError(
                "no registration response from remote".into(),
            )))
        }
    };

    match ProtoCommand::serialize(resp) {
        Some(ProtoCommand::REGISTERED) => Ok(()),
        Some(ProtoCommand::RegisterErr(msg)) => Err(Box::new(GenericError(format!(
            "registration rejected: {msg}"
        )))),
        _ => Err(Box::new(GenericError(
            "unexpected registration response".into(),
        ))),
    }
}

async fn ensure_tls_cert(
    config: &mut LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    if !config.tls_cert.is_empty() {
        return Ok(());
    }

    let cache_path = config.cert_cache_path.clone().unwrap_or_else(|| {
        cert::cert_cache_path(&config.remote_host, config.remote_quic_server_addr.port())
    });

    config.tls_cert = cert::load_or_fetch_cert(
        &config.remote_host,
        config.remote_quic_server_addr,
        &cache_path,
    )
    .await?;

    Ok(())
}

async fn setup_quic_connection(
    config: &LocalConfig,
) -> Result<s2n_quic::connection::Connection, Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_client = quic::new_quic_connection(
        config.remote_quic_server_addr,
        &config.tls_cert,
        &config.remote_host,
    )
    .await?;
    quic_client.keep_alive(true)?;
    log::debug!(
        "Connected to remote quic server {} ({})",
        config.remote_host,
        config.remote_quic_server_addr
    );
    Ok(quic_client)
}

async fn perform_handshake(
    command_stream: &mut BidirectionalStream,
) -> Result<SocketAddr, Box<dyn Error + Send + Sync + 'static>> {
    let handshake_data = receive_handshake_data(command_stream).await?;
    let cmd = serialize_handshake_command(handshake_data)?;

    log::debug!("Handshake complete");

    match cmd {
        ProtoCommand::CONNECTED(socket_addr) => Ok(socket_addr),
        _ => Err(Box::new(GenericError(
            "Invalid command from remote instance".to_string(),
        ))),
    }
}

async fn receive_handshake_data(
    command_stream: &mut BidirectionalStream,
) -> Result<Bytes, Box<dyn Error + Send + Sync + 'static>> {
    match command_stream.receive().await {
        Ok(Some(data)) => Ok(data),
        Err(_) | Ok(None) => Err(Box::new(GenericError(
            "Unable to receive handshake data".to_string(),
        ))),
    }
}

fn serialize_handshake_command(
    data: Bytes,
) -> Result<ProtoCommand, Box<dyn Error + Send + Sync + 'static>> {
    proto::ProtoCommand::serialize(data).ok_or_else(|| {
        let err: Box<dyn Error + Send + Sync + 'static> = Box::new(GenericError(
            "Unable to deserialize handshake data".to_string(),
        ));
        err
    })
}

fn spawn_tunnel_handler(
    quic_stream: BidirectionalStream,
    tcp_addr: SocketAddr,
    buffer_size: usize,
    http_mode: bool,
) {
    tokio::spawn(async move {
        if http_mode {
            if let Err(e) = handle_http_tunnel(quic_stream, tcp_addr).await {
                log::debug!("HTTP tunnel stream error: {e}");
            }
        } else if let Err(e) = handle_single_tunnel(quic_stream, tcp_addr, buffer_size).await {
            log::debug!("Tunnel stream error: {e}");
        }
    });
}

async fn handle_single_tunnel(
    mut quic_stream: BidirectionalStream,
    tcp_addr: SocketAddr,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut tcp_stream = TcpStream::connect(tcp_addr).await?;

    tokio::io::copy_bidirectional_with_sizes(
        &mut tcp_stream,
        &mut quic_stream,
        buffer_size,
        buffer_size,
    )
    .await?;

    Ok(())
}

/// HTTP mode / group mode: hyper parses requests on the QUIC stream, prints them,
/// and proxies to the local TCP target.
async fn handle_http_tunnel(
    quic_stream: BidirectionalStream,
    local_tcp_addr: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let io = TokioIo::new(quic_stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let local_tcp_addr = local_tcp_addr;
        async move { proxy_and_display(req, local_tcp_addr).await }
    });

    if let Err(e) = server_http1::Builder::new()
        .serve_connection(io, service)
        .await
    {
        log::debug!("HTTP connection on tunnel ended: {e}");
    }

    Ok(())
}

async fn proxy_and_display(
    req: Request<Incoming>,
    local_tcp_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to read request body: {e}")))?
        .to_bytes();

    display_http_request(&parts, &body_bytes);

    let outbound = Request::from_parts(parts, Full::new(body_bytes));
    let response = send_to_local(outbound, local_tcp_addr)
        .await
        .map_err(std::io::Error::other)?;

    let (res_parts, res_body) = response.into_parts();
    let res_bytes = res_body
        .collect()
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to read response body: {e}")))?
        .to_bytes();

    log::info!(
        "HTTP response: {} ({} bytes)",
        res_parts.status,
        res_bytes.len()
    );

    Ok(Response::from_parts(res_parts, Full::new(res_bytes)))
}

fn display_http_request(parts: &hyper::http::request::Parts, body: &Bytes) {
    println!("---------- HTTP request ----------");
    println!("{} {} {:?}", parts.method, parts.uri, parts.version);
    for (name, value) in parts.headers.iter() {
        let value = value.to_str().unwrap_or("<non-utf8>");
        println!("{name}: {value}");
    }
    if body.is_empty() {
        println!("(empty body)");
    } else {
        println!();
        match std::str::from_utf8(body) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("<binary body, {} bytes>", body.len()),
        }
    }
    println!("----------------------------------");
}

async fn send_to_local(
    req: Request<Full<Bytes>>,
    local_tcp_addr: SocketAddr,
) -> Result<Response<Incoming>, String> {
    let stream = TcpStream::connect(local_tcp_addr)
        .await
        .map_err(|e| format!("Unable to connect to local address {local_tcp_addr}: {e}"))?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = client_http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP handshake with local failed: {e}"))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("Local HTTP connection closed with error: {e}");
        }
    });

    sender
        .send_request(req)
        .await
        .map_err(|e| format!("Failed to send request to local: {e}"))
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_channel_sender: Sender<()>,
) {
    let (mut receiver, mut sender) = command_stream.split();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Err(e) = sender.send(ProtoCommand::CLOSED.deserialize()).await {
                log::warn!("Could not send CLOSED to remote reverse tunnel instance: {e}");
            }
        }
    });

    while let Ok(Some(cmd_data)) = receiver.receive().await {
        if let Some(cmd) = proto::ProtoCommand::serialize(cmd_data) {
            match cmd {
                ProtoCommand::CLOSED => {
                    log::info!("Remote tunnel instance has closed the connection");
                    let _ = close_channel_sender.send(()).await;
                    break;
                }
                ProtoCommand::ACK => {
                    log::info!("Closing local instance");
                    let _ = close_channel_sender.send(()).await;
                    break;
                }
                _ => {}
            }
        }
    }
}
