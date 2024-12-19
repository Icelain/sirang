pub mod config;
mod quic;

use std::error::Error;
use tokio::net::TcpStream;

use quic::quic_server;

pub async fn start_remote(
    config: config::RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut server = quic_server(&config).await?;

    log::info!("Quic server started");

    while let Some(mut connection) = server.accept().await {
        tokio::spawn(async move {
            while let Ok(Some(quic_stream)) = connection.accept_bidirectional_stream().await {
                // this is the client's socket address
                let remote_quic_addr = connection.remote_addr().unwrap();

                log::info!("Stream received from {remote_quic_addr}");

                let tcp_stream = match TcpStream::connect(config.forward_address).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::warn!("Error connecting to the remote tcp address: {e}");
                        return;
                    }
                };

                tokio::spawn(async move {
                    let mut quic_stream_c = quic_stream;
                    let mut tcp_stream_c = tcp_stream;

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
