pub mod config;
mod forward;
mod reverse;
use crate::common::TunnelType;
use std::error::Error;

use config::RemoteConfig;

pub async fn start_remote(
    config: RemoteConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    match config.tunnel_type {
        TunnelType::Forward => forward::forward_remote(config).await,
        TunnelType::Reverse => reverse::reverse_remote(config).await,
    }
}
