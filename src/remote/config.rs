use std::{net::SocketAddr, str::FromStr};

use crate::common::TunnelType;

pub struct RemoteConfig {
    pub tunnel_type: TunnelType,

    // only used for the forward tunnel
    pub forward_address: Option<SocketAddr>,

    // only used for the reverse tunnel
    pub tcp_address: Option<SocketAddr>,

    pub address: SocketAddr,
    pub tls_cert: String,
    pub tls_key: String,
    pub buffer_size: usize,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Forward,
            forward_address: None,
            tcp_address: None,
            address: SocketAddr::from_str("0.0.0.0:4433").unwrap(),
            tls_cert: String::new(),
            tls_key: String::new(),
            buffer_size: 1024 * 32,
        }
    }
}
