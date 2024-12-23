use std::{net::SocketAddr, str::FromStr};

use crate::common::{TunnelType, DEFAULT_BUFSIZE};

#[derive(Clone)]
pub struct RemoteConfig {
    pub tunnel_type: TunnelType,

    // only used for the forward tunnel
    pub tcp_forward_address: Option<SocketAddr>,

    // only used for the reverse tunnel
    pub tcp_reverse_address: Option<SocketAddr>,

    pub quic_address: SocketAddr,
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
                tls_cert: String::new(),
                tls_key: String::new(),
                buffer_size: DEFAULT_BUFSIZE,
            },

            TunnelType::Reverse => Self {
                tunnel_type: TunnelType::Reverse,
                tcp_forward_address: None,
                tcp_reverse_address: Some(SocketAddr::from_str("0.0.0.0:5000").unwrap()),
                quic_address: SocketAddr::from_str("0.0.0.0:4433").unwrap(),
                tls_key: String::new(),
                tls_cert: String::new(),
                buffer_size: DEFAULT_BUFSIZE,
            },
        }
    }
}
