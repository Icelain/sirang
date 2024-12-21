use crate::common::proto;
use crate::quic;

use super::config::RemoteConfig;
use s2n_quic::stream::BidirectionalStream;
use std::error::Error;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, Sender};

pub async fn reverse_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    let quic_address = config.quic_address;
    log::info!("Quic Server started on: {quic_address}");

    // only accept a single quic connection
    while let Some(mut quic_conn) = quic_srv.accept().await {
        let local_address = quic_conn.remote_addr().unwrap();
        log::info!("QUIC connection established with: {local_address}");

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

            let (close_channel_sender, mut close_channel_receiver) =
                mpsc::channel::<CloseAction>(1);
            tokio::spawn(handle_command_stream(quic_stream, close_channel_sender));

            // handle tcp stream

            loop {
                let (tcp_stream, tcp_addr) = tokio::select! {

                    Ok(res) = tcp_srv.accept() => {

                        res

                    },

                    Some(close_action) = close_channel_receiver.recv() => match close_action {

                        CloseAction::CloseProcess => {

                            log::info!("Ctrl-C, exiting...");
                            return Ok(());

                        },
                        CloseAction::CloseStream => {

                            log::info!("Closing stream");
                            break;

                        }

                    }

                };
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

                    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                        &mut tcp_stream_c,
                        &mut quic_data_stream_c,
                        buffer_size,
                        buffer_size,
                    )
                    .await
                    {
                        log::info!("Error during bidirectional copy: {e}");
                    }
                });
            }
        }
    }

    Ok(())
}

enum CloseAction {
    CloseProcess,
    CloseStream,
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_sender: Sender<CloseAction>,
) {
    let (mut receiver, mut sender) = command_stream.split();

    let close_sender_c = close_sender.clone();
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            if let Err(e) = sender.send(proto::ProtoCommand::CLOSED.deserialize()).await {
                log::warn!("Could not send CLOSED to local reverse tunnel instance:  {e}");
            }
        }

        close_sender_c
            .send(CloseAction::CloseProcess)
            .await
            .unwrap();
    });

    while let Ok(Some(cmd_data)) = receiver.receive().await {
        let cmd = match proto::ProtoCommand::serialize(cmd_data) {
            Some(cmd) => cmd,
            None => {
                continue;
            }
        };

        match cmd {
            proto::ProtoCommand::CLOSED => {
                log::info!("Local tunnel instance has closed the connection");
                close_sender.send(CloseAction::CloseStream).await.unwrap();
            }
            _ => {}
        }
    }
}
