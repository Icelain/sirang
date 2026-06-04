use s2n_quic::{client::Connect, Client, Connection, Server};
use std::{error::Error, net::SocketAddr};
use tokio::net::lookup_host;

use crate::errors::GenericError;

pub async fn new_quic_server(
    server_address: SocketAddr,
    tls_cert: &str,
    tls_key: &str,
) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> {
    let server = Server::builder()
        .with_io(server_address)?
        .with_tls((tls_cert, tls_key))?
        .start()?;

    Ok(server)
}

/// Establish a QUIC connection to `remote_addr`, using `server_name` for SNI
/// (typically the unresolved hostname so domain-backed remotes work).
pub async fn new_quic_connection(
    remote_addr: SocketAddr,
    tls_cert: &str,
    server_name: &str,
) -> Result<Connection, Box<dyn Error + Send + Sync + 'static>> {
    let quic_client = Client::builder()
        .with_tls(tls_cert)?
        .with_io("0.0.0.0:0")?
        .start()?;

    let connection = Connect::new(remote_addr).with_server_name(server_name);
    let conn = quic_client.connect(connection).await?;

    Ok(conn)
}

/// Resolve a `host:port` string to a socket address.
/// Prefers IPv4 when available.
pub async fn resolve_host_port(
    host_port: &str,
) -> Result<(String, u16, SocketAddr), Box<dyn Error + Send + Sync + 'static>> {
    let (host, port) = parse_host_port(host_port)?;
    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .map_err(|e| {
            Box::new(GenericError(format!(
                "DNS resolution failed for {host_port}: {e}"
            ))) as Box<dyn Error + Send + Sync + 'static>
        })?
        .collect();

    // Prefer IPv4 for broader compatibility with test certs / local remotes
    if let Some(addr) = addrs.iter().find(|a| a.is_ipv4()).copied() {
        return Ok((host, port, addr));
    }
    if let Some(addr) = addrs.into_iter().next() {
        return Ok((host, port, addr));
    }

    Err(Box::new(GenericError(format!(
        "No addresses resolved for {host_port}"
    ))))
}

/// Parse `host:port` or `[ipv6]:port` into host and port.
pub fn parse_host_port(
    host_port: &str,
) -> Result<(String, u16), Box<dyn Error + Send + Sync + 'static>> {
    // IPv6 in brackets: [2001:db8::1]:4433
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, port_part) = rest.split_once("]:").ok_or_else(|| {
            Box::new(GenericError(format!(
                "Invalid address '{host_port}', expected [ipv6]:port"
            ))) as Box<dyn Error + Send + Sync + 'static>
        })?;
        let port: u16 = port_part.parse().map_err(|_| {
            Box::new(GenericError(format!(
                "Invalid port in address '{host_port}'"
            ))) as Box<dyn Error + Send + Sync + 'static>
        })?;
        return Ok((host.to_string(), port));
    }

    // host:port (host may be a name or IPv4)
    let (host, port_str) = host_port.rsplit_once(':').ok_or_else(|| {
        Box::new(GenericError(format!(
            "Invalid address '{host_port}', expected host:port"
        ))) as Box<dyn Error + Send + Sync + 'static>
    })?;

    let port: u16 = port_str.parse().map_err(|_| {
        Box::new(GenericError(format!(
            "Invalid port in address '{host_port}'"
        ))) as Box<dyn Error + Send + Sync + 'static>
    })?;

    if host.is_empty() {
        return Err(Box::new(GenericError(format!(
            "Invalid address '{host_port}', empty host"
        ))));
    }

    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_ipv4() {
        let (h, p) = parse_host_port("127.0.0.1:4433").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 4433);
    }

    #[test]
    fn test_parse_host_port_domain() {
        let (h, p) = parse_host_port("example.com:4433").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 4433);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (h, p) = parse_host_port("[::1]:4433").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 4433);
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let (host, port, addr) = resolve_host_port("localhost:4433").await.unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 4433);
        assert_eq!(addr.port(), 4433);
    }
}
