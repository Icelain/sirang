use crate::common::TunnelType;
use std::{net::SocketAddr, str::FromStr};

pub struct LocalConfig {
    pub tunnel_type: TunnelType,
    pub local_tcp_server_addr: SocketAddr,
    pub remote_quic_server_addr: SocketAddr,
    pub tls_cert: String,
    pub buffer_size: usize,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Forward,
            local_tcp_server_addr: SocketAddr::from_str("127.0.0.1:8080").unwrap(),

            // remote_quic_server_addr is guaranteed to be properly set later
            remote_quic_server_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            // tls_cert is guaranteed to be properly set later
            tls_cert: String::new(),
            buffer_size: 1024 * 32,
        }
    }
}
