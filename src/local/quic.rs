use crate::local::config::LocalConfig;
use std::error::Error;

use s2n_quic::{client::Connect, Client, Connection};

pub async fn create_quic_conn(
    local_config: &LocalConfig,
) -> Result<Connection, Box<dyn Error + Send + Sync + 'static>> {
    let quic_client = Client::builder()
        .with_tls(local_config.tls_cert.as_str())?
        .with_io("0.0.0.0:0")?
        .start()?;

    let connection = Connect::new(local_config.remote_quic_server_addr)
        .with_server_name(local_config.remote_quic_server_addr.ip().to_string());
    let conn = quic_client.connect(connection).await?;

    Ok(conn)
}
