use s2n_quic::{client::Connect, Client, Connection, Server};
use std::{error::Error, net::SocketAddr};

pub async fn new_quic_server(
    server_address: SocketAddr,
    tls_cert: &str,
    tls_key: &str,
) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
    let server = Server::builder()
        .with_io(server_address)?
        .with_tls((tls_cert, tls_key))?
        .start()?;

    Ok(server)
}

pub async fn new_quic_connection(
    remote_addr: SocketAddr,
    tls_cert: &str,
) -> Result<Connection, Box<dyn Error + Send + Sync + 'static>> {
    let quic_client = Client::builder()
        .with_tls(tls_cert)?
        .with_io("0.0.0.0:0")?
        .start()?;

    let connection = Connect::new(remote_addr).with_server_name(remote_addr.ip().to_string());
    let conn = quic_client.connect(connection).await?;

    Ok(conn)
}
