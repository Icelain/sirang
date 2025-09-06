use super::config::LocalConfig;
use crate::{
    common::proto::{self, ProtoCommand},
    errors::GenericError,
    quic,
};
use bytes::Bytes;
use s2n_quic::stream::BidirectionalStream;
use std::error::Error;
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Sender},
};

pub async fn reverse_local(
    config: LocalConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_client = setup_quic_connection(&config).await?;
    let mut command_stream = quic_client.open_bidirectional_stream().await?;

    let remote_tcp_address_port = perform_handshake(&mut command_stream).await?;
    log::info!(
        "Access from {}:{}",
        config.remote_quic_server_addr.ip(),
        remote_tcp_address_port
    );

    let (close_channel_sender, mut close_channel_receiver) = channel::<()>(1);
    tokio::spawn(handle_command_stream(command_stream, close_channel_sender));

    loop {
        let server_created_quic_bd_stream = tokio::select! {
            bd_stream = quic_client.accept_bidirectional_stream() => match bd_stream? {
                Some(s) => s,
                None => break,
            },
            _ = close_channel_receiver.recv() => break,
        };

        spawn_tunnel_handler(
            server_created_quic_bd_stream,
            config.local_tcp_server_addr,
            config.buffer_size,
        );
    }
    Ok(())
}

async fn setup_quic_connection(
    config: &LocalConfig,
) -> Result<s2n_quic::connection::Connection, Box<dyn Error + Send + Sync + 'static>> {
    let mut quic_client =
        quic::new_quic_connection(config.remote_quic_server_addr, &config.tls_cert).await?;
    quic_client.keep_alive(true)?;
    log::debug!("Connected to remote quic server");
    Ok(quic_client)
}

async fn perform_handshake(
    command_stream: &mut BidirectionalStream,
) -> Result<u16, Box<dyn Error + Send + Sync + 'static>> {
    let handshake_data = receive_handshake_data(command_stream).await?;
    let cmd = serialize_handshake_command(handshake_data)?;

    log::debug!("Handshake complete");

    match cmd {
        ProtoCommand::CONNECTED(socket_addr) => Ok(socket_addr.port()),
        _ => Err(Box::new(GenericError(
            "Invalid command from remote instance".to_string(),
        ))),
    }
}

async fn receive_handshake_data(
    command_stream: &mut BidirectionalStream,
) -> Result<Bytes, Box<dyn Error + Send + Sync + 'static>> {
    match command_stream.receive().await {
        Ok(Some(data)) => Ok(data),
        Err(_) | Ok(None) => Err(Box::new(GenericError(
            "Unable to receive handshake data".to_string(),
        ))),
    }
}

fn serialize_handshake_command(
    data: Bytes,
) -> Result<ProtoCommand, Box<dyn Error + Send + Sync + 'static>> {
    proto::ProtoCommand::serialize(data).ok_or_else(|| {
        let err: Box<dyn Error + Send + Sync + 'static> = Box::new(GenericError(
            "Unable to deserialize handshake data".to_string(),
        ));
        err
    })
}

fn spawn_tunnel_handler(
    quic_stream: BidirectionalStream,
    tcp_addr: SocketAddr,
    buffer_size: usize,
) {
    tokio::spawn(async move {
        if let Err(e) = handle_single_tunnel(quic_stream, tcp_addr, buffer_size).await {
            log::debug!("Error while bidirectional copy: {e}");
        }
    });
}

async fn handle_single_tunnel(
    mut quic_stream: BidirectionalStream,
    tcp_addr: SocketAddr,
    buffer_size: usize,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut tcp_stream = TcpStream::connect(tcp_addr).await?;

    tokio::io::copy_bidirectional_with_sizes(
        &mut tcp_stream,
        &mut quic_stream,
        buffer_size,
        buffer_size,
    )
    .await?;

    Ok(())
}

async fn handle_command_stream(
    command_stream: BidirectionalStream,
    close_channel_sender: Sender<()>,
) {
    let (mut receiver, mut sender) = command_stream.split();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            if let Err(e) = sender.send(ProtoCommand::CLOSED.deserialize()).await {
                log::warn!("Could not send CLOSED to remote reverse tunnel instance: {e}");
            }
        }
    });

    while let Ok(Some(cmd_data)) = receiver.receive().await {
        if let Some(cmd) = proto::ProtoCommand::serialize(cmd_data) {
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
}
