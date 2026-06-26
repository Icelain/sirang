//! Automatic TLS certificate exchange between remote and local instances.
//!
//! The remote serves its PEM certificate over a plain TCP port (QUIC port + 1 by
//! default). Local clients fetch and cache the cert on first connect so `--cert`
//! is not required on local commands.

use crate::errors::GenericError;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Default offset from the QUIC port for the cert download TCP server.
pub const CERT_PORT_OFFSET: u16 = 1;

/// Derive the certificate-serving address from the QUIC listen address.
pub fn cert_addr_from_quic(quic_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(quic_addr.ip(), quic_addr.port().saturating_add(CERT_PORT_OFFSET))
}

/// Start a background task that serves the PEM certificate to any connecting client.
pub async fn serve_cert(
    listen_addr: SocketAddr,
    cert_pem: String,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind(listen_addr).await?;
    log::info!("Certificate server listening on {listen_addr}");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    log::debug!("Serving certificate to {peer}");
                    let cert = cert_pem.clone();
                    tokio::spawn(async move {
                        if let Err(e) = stream.write_all(cert.as_bytes()).await {
                            log::warn!("Failed to send certificate to {peer}: {e}");
                            return;
                        }
                        let _ = stream.shutdown().await;
                    });
                }
                Err(e) => {
                    log::warn!("Certificate server accept error: {e}");
                }
            }
        }
    });

    Ok(())
}

/// Download the remote certificate over TCP.
pub async fn fetch_cert(
    cert_addr: SocketAddr,
) -> Result<String, Box<dyn Error + Send + Sync + 'static>> {
    log::debug!("Fetching certificate from {cert_addr}");
    let mut stream = TcpStream::connect(cert_addr).await.map_err(|e| {
        Box::new(GenericError(format!(
            "Unable to connect to certificate server at {cert_addr}: {e}"
        ))) as Box<dyn Error + Send + Sync + 'static>
    })?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let cert = String::from_utf8(buf).map_err(|e| {
        Box::new(GenericError(format!("Invalid certificate encoding: {e}")))
            as Box<dyn Error + Send + Sync + 'static>
    })?;

    if !cert.contains("BEGIN CERTIFICATE") {
        return Err(Box::new(GenericError(
            "Downloaded data does not look like a PEM certificate".to_string(),
        )));
    }

    Ok(cert)
}

/// Resolve a cache path for a remote host:port pair under `~/.sirang/certs/`.
pub fn cert_cache_path(remote_host: &str, remote_port: u16) -> PathBuf {
    let safe_host = remote_host.replace(['/', '\\', ':'], "_");
    let mut dir = dirs_path();
    dir.push("certs");
    dir.push(format!("{safe_host}_{remote_port}.pem"));
    dir
}

fn dirs_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".sirang");
        p
    } else {
        PathBuf::from(".sirang")
    }
}

/// Load a cached certificate if present, otherwise fetch from the remote and cache it.
pub async fn load_or_fetch_cert(
    remote_host: &str,
    remote_quic_addr: SocketAddr,
    cache_path: &Path,
) -> Result<String, Box<dyn Error + Send + Sync + 'static>> {
    if cache_path.exists() {
        log::info!("Using cached certificate at {}", cache_path.display());
        return Ok(std::fs::read_to_string(cache_path)?);
    }

    let cert_addr = SocketAddr::new(
        remote_quic_addr.ip(),
        remote_quic_addr.port().saturating_add(CERT_PORT_OFFSET),
    );
    let cert = fetch_cert(cert_addr).await?;

    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cache_path, &cert)?;
    log::info!(
        "Downloaded certificate from {remote_host} and cached at {}",
        cache_path.display()
    );

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn test_cert_addr_from_quic() {
        let quic = SocketAddr::from_str("127.0.0.1:4433").unwrap();
        let cert = cert_addr_from_quic(quic);
        assert_eq!(cert.port(), 4434);
        assert_eq!(cert.ip(), quic.ip());
    }

    #[tokio::test]
    async fn test_serve_and_fetch_cert() {
        let cert_pem = include_str!("../test_cert.pem").to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        serve_cert(addr, cert_pem.clone()).await.unwrap();
        // give the task a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let fetched = fetch_cert(addr).await.unwrap();
        assert!(fetched.contains("BEGIN CERTIFICATE"));
        assert_eq!(fetched, cert_pem);
    }

    #[test]
    fn test_cert_cache_path_sanitizes_host() {
        let p = cert_cache_path("example.com", 4433);
        let s = p.to_string_lossy();
        assert!(s.contains("example.com_4433.pem"));
        assert!(s.contains(".sirang"));
        let p2 = cert_cache_path("a/b:c", 1);
        let name = p2.file_name().unwrap().to_string_lossy();
        assert!(!name.contains('/'));
        assert!(name.contains("a_b_c_1.pem"));
    }

    #[tokio::test]
    async fn test_load_or_fetch_uses_cache() {
        let dir = std::env::temp_dir().join(format!("sirang_cert_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("cached.pem");
        let pem = include_str!("../test_cert.pem");
        std::fs::write(&cache, pem).unwrap();

        let addr = SocketAddr::from_str("127.0.0.1:1").unwrap();
        let loaded = load_or_fetch_cert("localhost", addr, &cache).await.unwrap();
        assert_eq!(loaded, pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_load_or_fetch_downloads_and_caches() {
        let cert_pem = include_str!("../test_cert.pem").to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cert_addr = listener.local_addr().unwrap();
        drop(listener);
        serve_cert(cert_addr, cert_pem.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // load_or_fetch uses quic_port + 1; bind cert server on that derived port via fake quic addr
        let quic_port = cert_addr.port().saturating_sub(CERT_PORT_OFFSET);
        let quic_addr = SocketAddr::new(cert_addr.ip(), quic_port);

        let dir = std::env::temp_dir().join(format!("sirang_cert_dl_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = dir.join("dl.pem");
        assert!(!cache.exists());

        let loaded = load_or_fetch_cert("localhost", quic_addr, &cache)
            .await
            .unwrap();
        assert_eq!(loaded, cert_pem);
        assert!(cache.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_fetch_cert_rejects_non_pem() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        serve_cert(addr, "not a cert".into()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(fetch_cert(addr).await.is_err());
    }
}
