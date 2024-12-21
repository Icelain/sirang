use crate::common::TunnelType;
use config::LocalConfig;

pub mod config;
mod forward;
mod reverse;

pub async fn start_local(
    config: LocalConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    return match config.tunnel_type {
        TunnelType::Forward => forward::forward_local(config).await,
        TunnelType::Reverse => reverse::reverse_local(config).await,
    };
}
