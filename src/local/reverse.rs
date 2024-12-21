use std::error::Error;
use tokio::net::TcpStream;

use crate::{
    common::proto::{self, ProtoCommand},
    errors::GenericError,
    quic,
};

use super::config::LocalConfig;

pub async fn reverse_local(
    config: LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_client =
        quic::new_quic_connection(config.remote_quic_server_addr, &config.tls_cert).await?;
    quic_client.keep_alive(true)?;

    log::info!("Connected to remote quic server");

    let mut connection_stream = quic_client.open_bidirectional_stream().await?;
    let handshake_data = match connection_stream.receive().await {
        Ok(Some(data)) => data,
        Err(_) | Ok(None) => {
            return Err(Box::new(GenericError(
                "Unable to receive handshake data".to_string(),
            )));
        }
    };

    let cmd = match proto::ProtoCommand::serialize(handshake_data) {
        Some(cmd) => cmd,
        None => {
            return Err(Box::new(GenericError(
                "Unable to serialize handshake data".to_string(),
            )));
        }
    };

    let ProtoCommand::CONNECTED(remote_tcp_address) = cmd;

    let server_created_quic_bd_stream = match quic_client.accept_bidirectional_stream().await? {
        Some(s) => s,
        None => {
            return Err(Box::new(GenericError(
                "Unable to accept bidirectional stream from remote reverse tunnel instance"
                    .to_string(),
            )));
        }
    };

    let tcp_stream = TcpStream::connect(config.local_tcp_server_addr).await?;

    let buffer_size = config.buffer_size;

    tokio::spawn(async move {
        let mut quic_stream_c = server_created_quic_bd_stream;
        let mut tcp_stream_c = tcp_stream;

        tokio::io::copy_bidirectional_with_sizes(
            &mut tcp_stream_c,
            &mut quic_stream_c,
            buffer_size,
            buffer_size,
        )
        .await;
    });

    // should be printed whether logging is on or off
    println!("Listening on {remote_tcp_address}");

    Ok(())
}
