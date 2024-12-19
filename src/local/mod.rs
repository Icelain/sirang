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

    // Bind a TCP listener to the specified local server address
    let tcp_listener = TcpListener::bind(local_config.local_tcp_server_addr).await?;

    // Continuously accept incoming TCP connections
    while let Ok((tcp_stream, _tcp_addr)) = tcp_listener.accept().await {
        // Open a new bidirectional QUIC stream for each incoming TCP connection
        let bidirectional_stream = quic_conn.open_bidirectional_stream().await?;

        // Spawn a new asynchronous task to handle the connection
        tokio::spawn(async move {
            // Create local copies of the streams to move into the async block
            let mut bidirectional_stream_c = bidirectional_stream;
            let mut tcp_stream_c = tcp_stream;

            // Perform bidirectional copying of data between TCP and QUIC streams
            // This allows for full-duplex communication between the streams
            if let Err(e) =
                tokio::io::copy_bidirectional(&mut bidirectional_stream_c, &mut tcp_stream_c).await
            {
                // Print any errors that occur during the data transfer
                log::warn!("Error occurred during bidirectional copy: {e}");
            }
        });
    }

    // Loop will run undlessly and never return Ok(())
    Ok(())
}
