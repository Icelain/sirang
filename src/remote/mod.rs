pub mod config;
mod quic;
use quic::quic_server;
use std::error::Error;
use tokio::net::TcpStream;

pub async fn start_remote(
    config: config::RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // Initialize the QUIC server using provided configuration
    let mut server = quic_server(&config).await?;
    log::info!("Quic server started");

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
                let tcp_stream = match TcpStream::connect(config.forward_address).await {
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
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut tcp_stream_c, &mut quic_stream_c).await
                    {
                        log::warn!("Error while copying from the tcp stream to quic stream: {e}");
                    }
                });
            }
        });
    }
    Ok(())
}
