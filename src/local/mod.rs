pub mod config;
mod quic;

use std::error::Error;
use tokio::net::TcpListener;

// Async function to start a local server that bridges TCP and QUIC connections
pub async fn start_local(
    // Configuration for the local server
    local_config: config::LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // Create a QUIC connection using the provided local configuration
    let mut quic_conn = quic::create_quic_conn(&local_config).await?;

    // Enable keep-alive to maintain the QUIC connection
    quic_conn.keep_alive(true)?;

    let buffer_size = local_config.buffer_size;
    log::info!("Quic connection established with remote server with buffer Size: {buffer_size}");

    // Bind a TCP listener to the specified local server address

    let local_tcp_server_addr = local_config.local_tcp_server_addr;
    let tcp_listener = TcpListener::bind(local_tcp_server_addr).await?;
    log::info!("Tunneled Tcp Server accessible at: {local_tcp_server_addr}");

    // Continuously accept incoming TCP connections
    while let Ok((tcp_stream, _tcp_addr)) = tcp_listener.accept().await {
        // Open a new bidirectional QUIC stream for each incoming TCP connection
        let quic_bidirectional_stream = quic_conn.open_bidirectional_stream().await?;

        let buffer_size = local_config.buffer_size;

        // Spawn a new asynchronous task to handle the connection
        tokio::spawn(async move {
            // Create local copies of the streams to move into the async block
            let mut quic_bidirectional_stream_c = quic_bidirectional_stream;
            let mut tcp_stream_c = tcp_stream;

            // Perform bidirectional copying of data between TCP and QUIC streams
            // This allows for full-duplex communication between the streams
            if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                &mut quic_bidirectional_stream_c,
                &mut tcp_stream_c,
                buffer_size,
                buffer_size,
            )
            .await
            {
                // Print any errors that occur during the data transfer
                log::warn!("Error occurred during bidirectional copy: {e}");
            }
        });
    }

    // Loop will run undlessly and never return Ok(())
    Ok(())
}
