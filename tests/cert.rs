//! Integration tests for certificate serving and caching.

use std::net::SocketAddr;
use std::str::FromStr;

use sirang::cert::{cert_addr_from_quic, fetch_cert, load_or_fetch_cert, serve_cert, CERT_PORT_OFFSET};

#[tokio::test]
async fn integration_serve_fetch_multiple_clients() {
    let pem = include_str!("../test_cert.pem").to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    serve_cert(addr, pem.clone()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = addr;
        handles.push(tokio::spawn(async move { fetch_cert(a).await.unwrap() }));
    }
    for h in handles {
        let got = h.await.unwrap();
        assert!(got.contains("BEGIN CERTIFICATE"));
        assert_eq!(got, pem);
    }
}

#[tokio::test]
async fn integration_load_or_fetch_roundtrip() {
    let pem = include_str!("../test_cert.pem").to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_addr = listener.local_addr().unwrap();
    drop(listener);
    serve_cert(cert_addr, pem.clone()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let quic = SocketAddr::new(cert_addr.ip(), cert_addr.port().saturating_sub(CERT_PORT_OFFSET));
    assert_eq!(cert_addr_from_quic(quic), cert_addr);

    let dir = std::env::temp_dir().join(format!("sirang_it_cert_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cache = dir.join("c.pem");

    let first = load_or_fetch_cert("localhost", quic, &cache).await.unwrap();
    assert_eq!(first, pem);
    // Second call hits cache even if cert server is gone — stop by using existing cache
    let second = load_or_fetch_cert("localhost", quic, &cache).await.unwrap();
    assert_eq!(second, pem);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn integration_cert_addr_offset() {
    let a = SocketAddr::from_str("0.0.0.0:4433").unwrap();
    assert_eq!(cert_addr_from_quic(a).port(), 4434);
}
