use super::config;
use crate::{cert, quic};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Connection;
use std::error::Error;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

pub async fn forward_local(
    mut local_config: config::LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    ensure_tls_cert(&mut local_config).await?;
    let quic_conn = setup_quic_connection(&local_config).await?;
    let tcp_listener = setup_tcp_listener(&local_config).await?;

    handle_incoming_connections(tcp_listener, quic_conn, local_config.buffer_size).await
}

async fn ensure_tls_cert(
    local_config: &mut config::LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    if !local_config.tls_cert.is_empty() {
        return Ok(());
    }

    let cache_path = local_config.cert_cache_path.clone().unwrap_or_else(|| {
        cert::cert_cache_path(
            &local_config.remote_host,
            local_config.remote_quic_server_addr.port(),
        )
    });

    local_config.tls_cert = cert::load_or_fetch_cert(
        &local_config.remote_host,
        local_config.remote_quic_server_addr,
        &cache_path,
    )
    .await?;

    Ok(())
}

async fn setup_quic_connection(
    local_config: &config::LocalConfig,
) -> Result<Connection, Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_conn = quic::new_quic_connection(
        local_config.remote_quic_server_addr,
        &local_config.tls_cert,
        &local_config.remote_host,
    )
    .await?;

    quic_conn.keep_alive(true)?;
    log::info!(
        "Quic connection established with {} ({}) buffer size: {}",
        local_config.remote_host,
        local_config.remote_quic_server_addr,
        local_config.buffer_size
    );

    Ok(quic_conn)
}

async fn setup_tcp_listener(
    local_config: &config::LocalConfig,
) -> Result<TcpListener, Box<dyn Error + Send + Sync + 'static>> {
    let local_tcp_server_addr = local_config.local_tcp_server_addr;
    let tcp_listener = TcpListener::bind(local_tcp_server_addr).await?;
    log::info!("Tunneled Tcp Server accessible at: {local_tcp_server_addr}");

    Ok(tcp_listener)
}

async fn handle_incoming_connections(
    tcp_listener: TcpListener,
    mut quic_conn: Connection,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    while let Ok((tcp_stream, _tcp_addr)) = tcp_listener.accept().await {
        let quic_bidirectional_stream = quic_conn.open_bidirectional_stream().await?;
        spawn_connection_handler(tcp_stream, quic_bidirectional_stream, buffer_size);
    }

    Ok(())
}

fn spawn_connection_handler(
    tcp_stream: TcpStream,
    quic_bidirectional_stream: BidirectionalStream,
    buffer_size: usize,
) {
    tokio::spawn(async move {
        if let Err(e) =
            handle_single_connection(tcp_stream, quic_bidirectional_stream, buffer_size).await
        {
            log::warn!("Error occurred during bidirectional copy: {e}");
        }
    });
}

async fn handle_single_connection(
    mut tcp_stream: TcpStream,
    mut quic_bidirectional_stream: BidirectionalStream,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    tokio::io::copy_bidirectional_with_sizes(
        &mut quic_bidirectional_stream,
        &mut tcp_stream,
        buffer_size,
        buffer_size,
    )
    .await?;

    Ok(())
}
