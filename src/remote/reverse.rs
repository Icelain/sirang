use super::config::RemoteConfig;
use crate::common::proto;
use crate::quic;
use s2n_quic::stream::BidirectionalStream;
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, channel, Sender};
use tokio::sync::Mutex;

#[derive(Debug)]
enum CloseAction {
    CloseProcess,
    CloseStream,
}

pub async fn reverse_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    let quic_address = config.quic_address;
    log::info!("Quic Server started on: {quic_address}");

    // Create a channel for the global Ctrl-C handler
    let (global_shutdown_tx, mut global_shutdown_rx) = channel::<()>(1);

    // Spawn a global Ctrl-C handler
    let global_shutdown_tx_clone = global_shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            log::info!("Received Ctrl-C signal, initiating shutdown...");
            let _ = global_shutdown_tx_clone.send(()).await;
        }
    });

    loop {
        let (close_channel_entry_sender, mut close_channel_entry_receiver) =
            channel::<CloseAction>(1);

        let mut quic_conn = tokio::select! {
            Some(qc) = quic_srv.accept() => qc,
            _ = close_channel_entry_receiver.recv() => break,
            _ = global_shutdown_rx.recv() => {
                log::info!("Global shutdown signal received, exiting...");
                return Ok(());
            }
        };

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

            let (close_channel_tcpwait_sender, mut close_channel_tcpwait_receiver) =
                mpsc::channel::<CloseAction>(1);

            let global_shutdown_tx_stream = global_shutdown_tx.clone();
            tokio::spawn(handle_command_stream(
                quic_stream,
                close_channel_tcpwait_sender.clone(),
                close_channel_entry_sender.clone(),
                global_shutdown_tx_stream,
            ));

            loop {
                let (tcp_stream, tcp_addr) = tokio::select! {
                    Ok(res) = tcp_srv.accept() => res,
                    Some(close_action) = close_channel_tcpwait_receiver.recv() => {
                        match close_action {
                            CloseAction::CloseProcess => {
                                log::info!("Received close process signal, exiting...");
                                return Ok(());
                            },
                            CloseAction::CloseStream => {
                                log::info!("Client disconnected, accepting new connections...");
                                break;
                            }
                        }
                    },
                    _ = global_shutdown_rx.recv() => {
                        log::info!("Global shutdown signal received in TCP accept loop, exiting...");
                        return Ok(());
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

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_tcpwait_sender: Sender<CloseAction>,
    close_entry_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    let (mut receiver, sender) = command_stream.split();
    let sender_arc = Arc::new(Mutex::new(sender));
    let sender_arc_c = sender_arc.clone();
    let close_tcpwait_sender_c = close_tcpwait_sender.clone();
    let global_shutdown_tx_c = global_shutdown_tx.clone();

    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            let mut guard = sender_arc_c.lock().await;

            let _ = guard.send(proto::ProtoCommand::CLOSED.deserialize()).await;

            let _ = guard.flush().await;
            drop(guard);

            let _ = close_tcpwait_sender_c.send(CloseAction::CloseProcess).await;
            let _ = close_entry_sender.send(CloseAction::CloseProcess).await;
            let _ = global_shutdown_tx_c.send(()).await;
        }
    });

    while let Ok(Some(cmd_data)) = receiver.receive().await {
        log::info!("Received command from client");

        let cmd = match proto::ProtoCommand::serialize(cmd_data) {
            Some(cmd) => cmd,
            None => {
                log::warn!("Received invalid command data");
                continue;
            }
        };

        match cmd {
            proto::ProtoCommand::CLOSED => {
                log::info!("Local tunnel instance has closed the connection");

                let mut guard = sender_arc.lock().await;

                if let Err(e) = guard.send(proto::ProtoCommand::ACK.deserialize()).await {
                    log::warn!("Failed to send ACK: {e}");
                }

                drop(guard);

                if let Err(e) = close_tcpwait_sender.send(CloseAction::CloseStream).await {
                    log::warn!("Failed to send CloseStream action: {e}");
                }

                break;
            }
            _ => {
                log::debug!("Received unhandled command");
            }
        }
    }
}
