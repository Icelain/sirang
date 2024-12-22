use s2n_quic::stream::BidirectionalStream;
use std::error::Error;
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
};

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

    let mut command_stream = quic_client.open_bidirectional_stream().await?;

    let handshake_data = match command_stream.receive().await {
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

    log::info!("Handshake complete");

    let remote_tcp_address = match cmd {
        ProtoCommand::CONNECTED(socket_addr) => socket_addr,
        _ => {
            return Err(Box::new(GenericError(
                "Invalid command from remote instance".to_string(),
            )));
        }
    };

    let (close_channel_sender, mut close_channel_receiver) = channel::<()>(1);
    tokio::spawn(handle_command_stream(command_stream, close_channel_sender));

    // should be printed whether logging is on or off
    println!("Listening on {remote_tcp_address}");

    loop {
        let server_created_quic_bd_stream = tokio::select! {

            bd_stream = quic_client.accept_bidirectional_stream() => match bd_stream?{
                Some(s) => s,
                None => {
                    break;
                }
            },
            _ = close_channel_receiver.recv() => {

                break;

            }

        };

        let tcp_stream = TcpStream::connect(config.local_tcp_server_addr).await?;

        let buffer_size = config.buffer_size;

        tokio::spawn(async move {
            let mut quic_stream_c = server_created_quic_bd_stream;
            let mut tcp_stream_c = tcp_stream;

            if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                &mut tcp_stream_c,
                &mut quic_stream_c,
                buffer_size,
                buffer_size,
            )
            .await
            {
                log::info!("Error while bidirectional copy: {e}");
            }
        });
    }

    Ok(())
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_channel_sender: Sender<()>,
) {
    let (mut receiver, mut sender) = command_stream.split();

    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            if let Err(e) = sender.send(ProtoCommand::CLOSED.deserialize()).await {
                log::warn!("Could not send CLOSED to remote reverse tunnel instance: {e}");
            }
        }
    });

    while let Ok(Some(cmd_data)) = receiver.receive().await {
        let cmd = match proto::ProtoCommand::serialize(cmd_data) {
            Some(cmd) => cmd,
            None => {
                continue;
            }
        };

        match cmd {
            ProtoCommand::CLOSED => {
                log::info!("Remote tunnel instance has closed the connection");
                close_channel_sender.send(()).await.unwrap();
                break;
            }
            ProtoCommand::ACK => {
                log::info!("Closing local instance");
                close_channel_sender.send(()).await.unwrap();
                break;
            }
            _ => {}
        }
    }
}
