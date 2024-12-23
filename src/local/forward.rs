use super::config;
use crate::quic;
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Connection;
use std::error::Error;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

// Main function to start the local forwarding server
pub async fn forward_local(
    local_config: config::LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let quic_conn = setup_quic_connection(&local_config).await?;
    let tcp_listener = setup_tcp_listener(&local_config).await?;

    handle_incoming_connections(tcp_listener, quic_conn, local_config.buffer_size).await
}

// Set up the QUIC connection with the remote server
async fn setup_quic_connection(
    local_config: &config::LocalConfig,
) -> Result<Connection, Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_conn =
        quic::new_quic_connection(local_config.remote_quic_server_addr, &local_config.tls_cert)
            .await?;

    quic_conn.keep_alive(true)?;
    log::info!(
        "Quic connection established with remote server with buffer Size: {}",
        local_config.buffer_size
    );

    Ok(quic_conn)
}

// Set up the TCP listener for incoming connections
async fn setup_tcp_listener(
    local_config: &config::LocalConfig,
) -> Result<TcpListener, Box<dyn Error + Send + Sync + 'static>> {
    let local_tcp_server_addr = local_config.local_tcp_server_addr;
    let tcp_listener = TcpListener::bind(local_tcp_server_addr).await?;
    log::info!("Tunneled Tcp Server accessible at: {local_tcp_server_addr}");

    Ok(tcp_listener)
}

// Handle all incoming TCP connections and forward them to QUIC streams
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

// Spawn a new task to handle an individual connection
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

// Handle a single connection's bidirectional copying
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
