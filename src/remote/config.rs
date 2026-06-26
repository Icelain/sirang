use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use crate::common::{TunnelType, DEFAULT_BUFSIZE};
use crate::remote::groups::{AuthConfig, TunnelGroups};

#[derive(Clone)]
pub struct RemoteConfig {
    pub tunnel_type: TunnelType,

    // only used for the forward tunnel
    pub tcp_forward_address: Option<SocketAddr>,

    // only used for the reverse tunnel (legacy per-client TCP listen)
    pub tcp_reverse_address: Option<SocketAddr>,

    pub quic_address: SocketAddr,
    /// Address of the plain-TCP certificate server. Defaults to QUIC port + 1.
    pub cert_address: Option<SocketAddr>,
    pub tls_cert: String,
    pub tls_key: String,
    pub buffer_size: usize,

    /// Shared HTTP listen address for reverst-style reverse proxy (optional).
    pub http_address: Option<SocketAddr>,
    /// Tunnel groups for HTTP load-balanced reverse mode.
    pub tunnel_groups: Option<TunnelGroups>,
    /// Path groups were loaded from (for logging).
    pub groups_path: Option<PathBuf>,
    /// Optional management HTTP address for /metrics and /healthz.
    pub management_address: Option<SocketAddr>,
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
                http_address: None,
                tunnel_groups: None,
                groups_path: None,
                management_address: None,
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
                http_address: None,
                tunnel_groups: None,
                groups_path: None,
                management_address: None,
            },
        }
    }

    pub fn cert_listen_addr(&self) -> SocketAddr {
        self.cert_address
            .unwrap_or_else(|| crate::cert::cert_addr_from_quic(self.quic_address))
    }

    /// Reverst-style mode: shared HTTP front + tunnel groups.
    pub fn is_group_http_mode(&self) -> bool {
        self.http_address.is_some() && self.tunnel_groups.is_some()
    }

    pub fn set_default_group(
        &mut self,
        name: &str,
        hosts: Vec<String>,
        auth: AuthConfig,
    ) {
        self.tunnel_groups = Some(TunnelGroups::single_group(name, hosts, auth));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::TunnelType;
    use crate::remote::groups::AuthConfig;

    #[test]
    fn test_remote_config_defaults() {
        let f = RemoteConfig::new(&TunnelType::Forward);
        assert!(f.tcp_forward_address.is_none());
        assert!(!f.is_group_http_mode());
        assert_eq!(f.quic_address.port(), 4433);
        assert_eq!(f.cert_listen_addr().port(), 4434);

        let r = RemoteConfig::new(&TunnelType::Reverse);
        assert!(r.tcp_reverse_address.is_some());
        assert!(!r.is_group_http_mode());
    }

    #[test]
    fn test_group_http_mode_flag() {
        let mut r = RemoteConfig::new(&TunnelType::Reverse);
        r.http_address = Some("127.0.0.1:8181".parse().unwrap());
        assert!(!r.is_group_http_mode());
        r.set_default_group("localhost", vec!["localhost".into()], AuthConfig::default());
        assert!(r.is_group_http_mode());
    }
}
