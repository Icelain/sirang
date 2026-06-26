//! Integration test for forward tunnel TCP copy over QUIC.

use std::time::Duration;

use sirang::common::TunnelType;
use sirang::local;
use sirang::local::config::LocalConfig;
use sirang::remote;
use sirang::remote::config::RemoteConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn forward_tunnel_echo() {
    // Backend echo server (remote forward target)
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = backend.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });

    let quic_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quic_addr = quic_l.local_addr().unwrap();
    drop(quic_l);
    let local_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_l.local_addr().unwrap();
    drop(local_l);

    let mut remote_cfg = RemoteConfig::new(&TunnelType::Forward);
    remote_cfg.tls_cert = include_str!("../test_cert.pem").into();
    remote_cfg.tls_key = include_str!("../test_key.pem").into();
    remote_cfg.quic_address = quic_addr;
    remote_cfg.tcp_forward_address = Some(backend_addr);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = remote::start_remote(remote_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(120)).await;

    let mut local_cfg = LocalConfig::default();
    local_cfg.tunnel_type = TunnelType::Forward;
    local_cfg.remote_host = "localhost".into();
    local_cfg.remote_quic_server_addr = quic_addr;
    local_cfg.tls_cert = include_str!("../test_cert.pem").into();
    local_cfg.local_tcp_server_addr = local_addr;

    tokio::spawn(async move {
        let _ = local::start_local(local_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut client = TcpStream::connect(local_addr).await.unwrap();
    client.write_all(b"ping-forward").await.unwrap();
    let mut buf = [0u8; 32];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping-forward");
}
