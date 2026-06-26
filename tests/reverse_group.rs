//! Integration tests for reverst-style reverse group HTTP mode.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sirang::common::TunnelType;
use sirang::local;
use sirang::local::config::LocalConfig;
use sirang::remote;
use sirang::remote::config::RemoteConfig;
use sirang::remote::groups::AuthConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

async fn spawn_tiny_http(body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let body = body;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    addr
}

async fn http_get(addr: SocketAddr, host: &str, path: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let status = std::str::from_utf8(&buf)
        .unwrap_or("")
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, buf)
}

#[tokio::test]
async fn reverse_group_http_proxy_and_metrics() {
    let svc = spawn_tiny_http(b"hello-group").await;

    let mut remote_cfg = RemoteConfig::new(&TunnelType::Reverse);
    remote_cfg.tls_cert = include_str!("../test_cert.pem").into();
    remote_cfg.tls_key = include_str!("../test_key.pem").into();
    remote_cfg.quic_address = "127.0.0.1:0".parse().unwrap();
    // Bind explicit ports for HTTP + management via listeners first
    let http_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_l.local_addr().unwrap();
    drop(http_l);
    let mgmt_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mgmt_addr = mgmt_l.local_addr().unwrap();
    drop(mgmt_l);
    let quic_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quic_addr = quic_l.local_addr().unwrap();
    drop(quic_l);

    remote_cfg.quic_address = quic_addr;
    remote_cfg.http_address = Some(http_addr);
    remote_cfg.management_address = Some(mgmt_addr);
    remote_cfg.set_default_group(
        "localhost",
        vec!["localhost".into(), "127.0.0.1".into()],
        AuthConfig::default(),
    );

    let ready = Arc::new(Notify::new());
    let ready2 = ready.clone();
    tokio::spawn(async move {
        // small delay so ports are free
        tokio::time::sleep(Duration::from_millis(20)).await;
        ready2.notify_one();
        let _ = remote::start_remote(remote_cfg).await;
    });
    ready.notified().await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut local_cfg = LocalConfig::default();
    local_cfg.tunnel_type = TunnelType::Reverse;
    local_cfg.remote_host = "localhost".into();
    local_cfg.remote_quic_server_addr = quic_addr;
    local_cfg.tls_cert = include_str!("../test_cert.pem").into();
    local_cfg.local_tcp_server_addr = svc;
    local_cfg.tunnel_group = Some("localhost".into());

    tokio::spawn(async move {
        let _ = local::start_local(local_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (status, body) = http_get(http_addr, "localhost", "/hi").await;
    assert_eq!(status, 200, "body={}", String::from_utf8_lossy(&body));
    assert!(body.windows(b"hello-group".len()).any(|w| w == b"hello-group"));
    assert!(
        std::str::from_utf8(&body).unwrap_or("").to_ascii_lowercase().contains("via"),
        "expected Via header in response"
    );

    // unknown host -> 502
    let (status, _) = http_get(http_addr, "no-such-host.invalid", "/").await;
    assert_eq!(status, 502);

    // metrics endpoint
    let mut s = TcpStream::connect(mgmt_addr).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut metrics_body = Vec::new();
    s.read_to_end(&mut metrics_body).await.unwrap();
    let metrics_text = String::from_utf8_lossy(&metrics_body);
    assert!(metrics_text.contains("sirang_up 1"), "{metrics_text}");
    assert!(metrics_text.contains("sirang_proxy_requests_total"), "{metrics_text}");
    assert!(metrics_text.contains("registrations_total"), "{metrics_text}");
}

#[tokio::test]
async fn reverse_group_rejects_bad_auth() {
    let mut remote_cfg = RemoteConfig::new(&TunnelType::Reverse);
    remote_cfg.tls_cert = include_str!("../test_cert.pem").into();
    remote_cfg.tls_key = include_str!("../test_key.pem").into();

    let http_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_l.local_addr().unwrap();
    drop(http_l);
    let quic_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quic_addr = quic_l.local_addr().unwrap();
    drop(quic_l);

    remote_cfg.quic_address = quic_addr;
    remote_cfg.http_address = Some(http_addr);
    remote_cfg.set_default_group(
        "secure",
        vec!["localhost".into()],
        sirang::remote::groups::AuthConfig {
            basic: Some(sirang::remote::groups::BasicAuth {
                username: "user".into(),
                password: "pass".into(),
            }),
            bearer: None,
        },
    );

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = remote::start_remote(remote_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut local_cfg = LocalConfig::default();
    local_cfg.tunnel_type = TunnelType::Reverse;
    local_cfg.remote_host = "localhost".into();
    local_cfg.remote_quic_server_addr = quic_addr;
    local_cfg.tls_cert = include_str!("../test_cert.pem").into();
    local_cfg.local_tcp_server_addr = "127.0.0.1:9".parse().unwrap();
    local_cfg.tunnel_group = Some("secure".into());
    local_cfg.authorization = Some("Basic dXNlcjp3cm9uZw==".into()); // user:wrong

    let result = local::start_local(local_cfg).await;
    assert!(result.is_err(), "expected registration failure");
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.to_ascii_lowercase().contains("unauthor") || msg.contains("rejected"),
        "msg={msg}"
    );
}
