use crate::common::{TunnelType, DEFAULT_BUFSIZE};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone)]
pub struct LocalConfig {
    pub tunnel_type: TunnelType,
    pub local_tcp_server_addr: SocketAddr,
    /// Original remote host (name or IP) used for SNI and cert cache keys.
    pub remote_host: String,
    /// Resolved remote QUIC server address.
    pub remote_quic_server_addr: SocketAddr,
    pub tls_cert: String,
    pub buffer_size: usize,
    /// Optional override for cert cache path; default is ~/.sirang/certs/...
    pub cert_cache_path: Option<PathBuf>,
    /// When true (legacy reverse), parse HTTP on streams and print requests.
    pub http_mode: bool,
    /// Tunnel group to join (reverst-style). When set, uses REGISTER handshake
    /// and always proxies HTTP to local_tcp_server_addr.
    pub tunnel_group: Option<String>,
    /// Optional Authorization for group registration ("Basic …" or "Bearer …").
    pub authorization: Option<String>,
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
            cert_cache_path: None,
            http_mode: false,
            tunnel_group: None,
            authorization: None,
        }
    }
}
