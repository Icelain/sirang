use super::config::RemoteConfig;
use crate::{common::proto, quic};
use s2n_quic::stream::BidirectionalStream;
use std::{error::Error, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{
        mpsc::{self, channel, Sender},
        Mutex,
    },
};

#[derive(Debug)]
enum CloseAction {
    CloseProcess,
    CloseStream,
}

pub async fn reverse_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_srv = setup_quic_server(&config).await?;
    let (global_shutdown_tx, mut global_shutdown_rx) = setup_global_shutdown();

    handle_connections(
        &mut quic_srv,
        config,
        global_shutdown_tx,
        &mut global_shutdown_rx,
    )
    .await
}

async fn setup_quic_server(
    config: &RemoteConfig,
) -> Result<s2n_quic::Server, Box<dyn Error + Send + Sync + 'static>> {
    let quic_srv =
        quic::new_quic_server(config.quic_address, &config.tls_cert, &config.tls_key).await?;

    log::info!("Quic Server started on: {}", config.quic_address);
    log::info!(
        "Tcp Server listening on: {}",
        config.tcp_reverse_address.unwrap()
    );

    Ok(quic_srv)
}

fn setup_global_shutdown() -> (Sender<()>, mpsc::Receiver<()>) {
    let (global_shutdown_tx, global_shutdown_rx) = channel::<()>(1);
    let global_shutdown_tx_clone = global_shutdown_tx.clone();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            log::info!("Received Ctrl-C signal, initiating shutdown...");
            let _ = global_shutdown_tx_clone.send(()).await;
        }
    });

    (global_shutdown_tx, global_shutdown_rx)
}

async fn handle_connections(
    quic_srv: &mut s2n_quic::Server,
    config: RemoteConfig,
    global_shutdown_tx: Sender<()>,
    global_shutdown_rx: &mut mpsc::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
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

        if let Ok(client_address) = quic_conn.remote_addr() {
            log::debug!("QUIC connection established with: {client_address}");
            handle_quic_connection(
                &mut quic_conn,
                config.clone(),
                close_channel_entry_sender,
                global_shutdown_tx.clone(),
                global_shutdown_rx,
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_quic_connection(
    quic_conn: &mut s2n_quic::Connection,
    config: RemoteConfig,
    close_entry_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
    global_shutdown_rx: &mut mpsc::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    if let Ok(Some(mut command_stream)) = quic_conn.accept_bidirectional_stream().await {
        let tcp_listener = setup_tcp_listener(&config).await?;
        send_connection_handshake(&mut command_stream, &config).await?;

        let (close_tcpwait_sender, mut close_tcpwait_receiver) = mpsc::channel::<CloseAction>(1);

        spawn_command_stream_handler(
            command_stream,
            close_tcpwait_sender.clone(),
            close_entry_sender,
            global_shutdown_tx,
        );

        handle_tcp_connections(
            tcp_listener,
            quic_conn,
            config.buffer_size,
            &mut close_tcpwait_receiver,
            global_shutdown_rx,
        )
        .await?;
    }
    Ok(())
}

async fn setup_tcp_listener(
    config: &RemoteConfig,
) -> Result<TcpListener, Box<dyn Error + Send + Sync + 'static>> {
    TcpListener::bind(config.tcp_reverse_address.unwrap())
        .await
        .map_err(|e| {
            log::warn!("Tcp Listener could not be created: {e}");
            Box::new(e) as Box<dyn Error + Send + Sync + 'static>
        })
}

async fn send_connection_handshake(
    command_stream: &mut BidirectionalStream,
    config: &RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let connected_msg =
        proto::ProtoCommand::CONNECTED(config.tcp_reverse_address.unwrap()).deserialize();
    command_stream.send(connected_msg).await.map_err(|e| {
        log::warn!(
            "Error while sending connect handshake message to local reverse tunnel instance: {e}"
        );
        Box::new(e) as Box<dyn Error + Send + Sync + 'static>
    })
}

async fn handle_tcp_connections(
    tcp_listener: TcpListener,
    quic_conn: &mut s2n_quic::Connection,
    buffer_size: usize,
    close_tcpwait_receiver: &mut mpsc::Receiver<CloseAction>,
    global_shutdown_rx: &mut mpsc::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    loop {
        let (tcp_stream, tcp_addr) = tokio::select! {
            Ok(res) = tcp_listener.accept() => res,
            Some(close_action) = close_tcpwait_receiver.recv() => {
                match close_action {
                    CloseAction::CloseProcess => {
                        log::info!("Received close process signal, exiting...");
                        return Ok(());
                    },
                    CloseAction::CloseStream => {
                        log::debug!("Client disconnected, accepting new connections...");
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
        spawn_stream_handler(quic_conn, tcp_stream, buffer_size).await?;
    }
    Ok(())
}

async fn spawn_stream_handler(
    quic_conn: &mut s2n_quic::Connection,
    tcp_stream: tokio::net::TcpStream,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let quic_data_stream = quic_conn.open_bidirectional_stream().await.map_err(|e| {
        log::warn!(
            "Unable to create bidirectional quic stream with local reverse tunnel instance: {e}"
        );
        Box::new(e) as Box<dyn Error + Send + Sync + 'static>
    })?;

    tokio::spawn(handle_stream_copy(
        tcp_stream,
        quic_data_stream,
        buffer_size,
    ));
    Ok(())
}

async fn handle_stream_copy(
    mut tcp_stream: tokio::net::TcpStream,
    mut quic_stream: BidirectionalStream,
    buffer_size: usize,
) {
    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
        &mut tcp_stream,
        &mut quic_stream,
        buffer_size,
        buffer_size,
    )
    .await
    {
        log::warn!("Error during bidirectional copy: {e}");
    }
}

fn spawn_command_stream_handler(
    command_stream: BidirectionalStream,
    close_tcpwait_sender: Sender<CloseAction>,
    close_entry_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    tokio::spawn(handle_command_stream(
        command_stream,
        close_tcpwait_sender,
        close_entry_sender,
        global_shutdown_tx,
    ));
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_tcpwait_sender: Sender<CloseAction>,
    close_entry_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    let (receiver, sender) = command_stream.split();
    let sender_arc = Arc::new(Mutex::new(sender));

    spawn_ctrl_c_handler(
        sender_arc.clone(),
        close_tcpwait_sender.clone(),
        close_entry_sender,
        global_shutdown_tx,
    );

    handle_command_receiver(receiver, sender_arc, close_tcpwait_sender).await;
}

fn spawn_ctrl_c_handler(
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
    close_entry_sender: Sender<CloseAction>,
    global_shutdown_tx: Sender<()>,
) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let mut guard = sender_arc.lock().await;
            let _ = guard.send(proto::ProtoCommand::CLOSED.deserialize()).await;
            let _ = guard.flush().await;
            drop(guard);

            let _ = close_tcpwait_sender.send(CloseAction::CloseProcess).await;
            let _ = close_entry_sender.send(CloseAction::CloseProcess).await;
            let _ = global_shutdown_tx.send(()).await;
        }
    });
}

async fn handle_command_receiver(
    mut receiver: s2n_quic::stream::ReceiveStream,
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
) {
    while let Ok(Some(cmd_data)) = receiver.receive().await {
        log::debug!("Received command from client");

        let cmd = match proto::ProtoCommand::serialize(cmd_data) {
            Some(cmd) => cmd,
            None => {
                log::warn!("Received invalid command data");
                continue;
            }
        };

        if let proto::ProtoCommand::CLOSED = cmd {
            log::debug!("Local tunnel instance has closed the connection");
            send_ack_and_close(sender_arc, close_tcpwait_sender).await;
            break;
        } else {
            log::debug!("Received unhandled command");
        }
    }
}

async fn send_ack_and_close(
    sender_arc: Arc<Mutex<s2n_quic::stream::SendStream>>,
    close_tcpwait_sender: Sender<CloseAction>,
) {
    let mut guard = sender_arc.lock().await;
    if let Err(e) = guard.send(proto::ProtoCommand::ACK.deserialize()).await {
        log::warn!("Failed to send ACK: {e}");
    }
    drop(guard);

    if let Err(e) = close_tcpwait_sender.send(CloseAction::CloseStream).await {
        log::warn!("Failed to send CloseStream action: {e}");
    }
}
