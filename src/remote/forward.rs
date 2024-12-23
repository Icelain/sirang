use super::config::RemoteConfig;
use crate::quic;
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn forward_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server = setup_quic_server(&config).await?;

    handle_incoming_connections(server, config).await
}

async fn setup_quic_server(
    config: &RemoteConfig,
) -> Result<s2n_quic::Server, Box<dyn Error + Send + Sync + 'static>> {
    let server =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    log::info!(
        "Quic server started at: {} with buffer size: {}",
        config.quic_address,
        config.buffer_size
    );

    Ok(server)
}

async fn handle_incoming_connections(
    mut server: s2n_quic::Server,
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    while let Some(connection) = server.accept().await {
        spawn_connection_handler(connection, config.clone());
    }
    Ok(())
}

fn spawn_connection_handler(mut connection: s2n_quic::Connection, config: RemoteConfig) {
    tokio::spawn(async move {
        while let Ok(Some(quic_stream)) = connection.accept_bidirectional_stream().await {
            if let Ok(remote_addr) = connection.remote_addr() {
                handle_stream(
                    quic_stream,
                    remote_addr,
                    config.tcp_forward_address.unwrap(),
                    config.buffer_size,
                )
                .await;
            }
        }
    });
}

async fn handle_stream(
    quic_stream: s2n_quic::stream::BidirectionalStream,
    remote_quic_addr: SocketAddr,
    tcp_forward_addr: SocketAddr,
    buffer_size: usize,
) {
    log::info!("Stream received from {remote_quic_addr}");

    let tcp_stream = match TcpStream::connect(tcp_forward_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            log::warn!("Error connecting to the remote tcp address: {e}");
            return;
        }
    };

    spawn_copy_handler(quic_stream, tcp_stream, buffer_size);
}

fn spawn_copy_handler(
    mut quic_stream: s2n_quic::stream::BidirectionalStream,
    mut tcp_stream: TcpStream,
    buffer_size: usize,
) {
    tokio::spawn(async move {
        if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
            &mut tcp_stream,
            &mut quic_stream,
            buffer_size,
            buffer_size,
        )
        .await
        {
            log::warn!("Error while bidirectional copy: {e}");
        }
    });
}
