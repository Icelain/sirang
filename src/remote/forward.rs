use super::config::RemoteConfig;
use crate::quic;
use std::error::Error;
use tokio::net::TcpStream;

pub async fn forward_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // Initialize the QUIC server using provided configuration
    let mut server =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;
    let buffer_size = config.buffer_size;
    let local_quic_address = config.quic_address;

    log::info!("Quic server started at: {local_quic_address} with buffer size: {buffer_size}");

    // Accept incoming QUIC connections in a loop
    while let Some(mut connection) = server.accept().await {
        // Spawn a new task for each connection to handle multiple clients
        tokio::spawn(async move {
            // Accept bidirectional streams from the current connection
            while let Ok(Some(quic_stream)) = connection.accept_bidirectional_stream().await {
                // Get the client's socket address for logging
                let remote_quic_addr = connection.remote_addr().unwrap();
                log::info!("Stream received from {remote_quic_addr}");

                // Attempt to establish TCP connection to the forward address
                let tcp_stream = match TcpStream::connect(config.tcp_forward_address.unwrap()).await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::warn!("Error connecting to the remote tcp address: {e}");
                        return;
                    }
                };

                // Spawn another task to handle the bidirectional copying between QUIC and TCP streams
                tokio::spawn(async move {
                    let mut quic_stream_c = quic_stream;
                    let mut tcp_stream_c = tcp_stream;

                    // Copy data bidirectionally between the QUIC and TCP streams
                    // This allows traffic to flow in both directions
                    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                        &mut tcp_stream_c,
                        &mut quic_stream_c,
                        buffer_size,
                        buffer_size,
                    )
                    .await
                    {
                        log::warn!("Error while bidirectional copy: {e}");
                    }
                });
            }
        });
    }
    Ok(())
}
