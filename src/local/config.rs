use crate::common::{TunnelType, DEFAULT_BUFSIZE};
use std::{net::SocketAddr, str::FromStr};

#[derive(Clone)]
pub struct LocalConfig {
    pub tunnel_type: TunnelType,
    pub local_tcp_server_addr: SocketAddr,
    /// Original remote host (name or IP) used for SNI.
    pub remote_host: String,
    /// Resolved remote QUIC server address.
    pub remote_quic_server_addr: SocketAddr,
    pub tls_cert: String,
    pub buffer_size: usize,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Forward,
            local_tcp_server_addr: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
            remote_host: String::new(),
            remote_quic_server_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            tls_cert: String::new(),
            buffer_size: DEFAULT_BUFSIZE,
        }
    }
}
