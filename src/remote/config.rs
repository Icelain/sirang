use std::{net::SocketAddr, str::FromStr};

use crate::common::{TunnelType, DEFAULT_BUFSIZE};

#[derive(Clone)]
pub struct RemoteConfig {
    pub tunnel_type: TunnelType,

    // only used for the forward tunnel
    pub tcp_forward_address: Option<SocketAddr>,

    // only used for the reverse tunnel (preferred listen address for clients)
    pub tcp_reverse_address: Option<SocketAddr>,

    pub quic_address: SocketAddr,
    /// Address of the plain-TCP certificate server. Defaults to QUIC port + 1.
    pub cert_address: Option<SocketAddr>,
    pub tls_cert: String,
    pub tls_key: String,
    pub buffer_size: usize,
}

impl RemoteConfig {
    pub fn new(tunnel_type: &TunnelType) -> Self {
        match tunnel_type {
            TunnelType::Forward => Self {
                tunnel_type: TunnelType::Forward,
                tcp_forward_address: None,
                tcp_reverse_address: None,
                quic_address: SocketAddr::from_str("0.0.0.0:4433").unwrap(),
                cert_address: None,
                tls_cert: String::new(),
                tls_key: String::new(),
                buffer_size: DEFAULT_BUFSIZE,
            },

            TunnelType::Reverse => Self {
                tunnel_type: TunnelType::Reverse,
                tcp_forward_address: None,
                tcp_reverse_address: Some(SocketAddr::from_str("0.0.0.0:5000").unwrap()),
                quic_address: SocketAddr::from_str("0.0.0.0:4433").unwrap(),
                cert_address: None,
                tls_key: String::new(),
                tls_cert: String::new(),
                buffer_size: DEFAULT_BUFSIZE,
            },
        }
    }

    pub fn cert_listen_addr(&self) -> SocketAddr {
        self.cert_address
            .unwrap_or_else(|| crate::cert::cert_addr_from_quic(self.quic_address))
    }
}
