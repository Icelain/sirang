use s2n_quic::Server;
use std::error::Error;

use crate::remote::config::RemoteConfig;

pub async fn quic_server(
    srv_config: &RemoteConfig,
) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
    let server = Server::builder()
        .with_io(srv_config.address)?
        .with_tls((srv_config.tls_cert.as_str(), srv_config.tls_key.as_str()))?
        .start()?;

    Ok(server)
}
