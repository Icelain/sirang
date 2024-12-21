use crate::common::proto;
use crate::quic;

use super::config::RemoteConfig;
use std::error::Error;
use tokio::net::TcpListener;

pub async fn reverse_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    let quic_address = config.quic_address;
    log::info!("Quic Server started on: {quic_address}");

    // only accept a single quic connection
    while let Some(mut quic_conn) = quic_srv.accept().await {
        if let Ok(Some(mut quic_stream)) = quic_conn.accept_bidirectional_stream().await {
            let tcp_srv = match TcpListener::bind(config.tcp_reverse_address.unwrap()).await {
                Ok(srv) => srv,
                Err(e) => {
                    log::warn!("Tcp Listener could not be created: {e}");
                    continue;
                }
            };

            let connected_msg =
                proto::ProtoCommand::CONNECTED(config.tcp_reverse_address.unwrap()).deserialize();
            if let Err(e) = quic_stream.send(connected_msg).await {
                log::warn!(
                    "Error while sending connect handshake message to local reverse tunnel instance: {e}"
                );
                continue;
            }

            // handle tcp stream
            while let Ok((tcp_stream, tcp_addr)) = tcp_srv.accept().await {
                log::info!("Stream received from {tcp_addr}");

                let quic_data_stream = match quic_conn.open_bidirectional_stream().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("Unable to create bidirectional quic stream with local reverse tunnel instance: {e}");
                        break;
                    }
                };

                let buffer_size = config.buffer_size;
                tokio::spawn(async move {
                    let mut tcp_stream_c = tcp_stream;
                    let mut quic_data_stream_c = quic_data_stream;

                    tokio::io::copy_bidirectional_with_sizes(
                        &mut tcp_stream_c,
                        &mut quic_data_stream_c,
                        buffer_size,
                        buffer_size,
                    )
                    .await;
                });
            }
        }
    }

    Ok(())
}
