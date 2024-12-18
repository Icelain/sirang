use std::{net::SocketAddr, str::FromStr};

pub struct RemoteConfig {
    pub forward_address: SocketAddr,
    pub address: SocketAddr,
    pub tls_cert: String,
    pub tls_key: String,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            forward_address: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            address: SocketAddr::from_str("0.0.0.0:4433").unwrap(),
            tls_cert: String::new(),
            tls_key: String::new(),
        }
    }
}
