#[cfg(test)]
mod quic_tests {

    use std::{net::SocketAddr, str::FromStr};

    use sirang::{
        common::proto::ProtoCommand,
        quic::{new_quic_connection, new_quic_server},
    };

    #[tokio::test]
    async fn test_create_new_quic_connection() {
        let server = new_quic_server(
            SocketAddr::from_str("127.0.0.1:0").unwrap(),
            include_str!(".././test_cert.pem"),
            include_str!(".././test_key.pem"),
        )
        .await
        .unwrap();

        let new_conn_result = new_quic_connection(
            server.local_addr().unwrap(),
            include_str!(".././test_cert.pem"),
            "localhost",
        )
        .await;
        assert!(new_conn_result.is_ok());
    }

    #[tokio::test]
    async fn test_create_new_quic_server() {
        let socket_addr_result = SocketAddr::from_str("127.0.0.1:0");
        assert!(socket_addr_result.is_ok());
        let socket_addr = socket_addr_result.unwrap();

        let new_server_result = new_quic_server(
            socket_addr,
            include_str!(".././test_cert.pem"),
            include_str!(".././test_key.pem"),
        )
        .await;
        assert!(new_server_result.is_ok());
    }

    #[tokio::test]
    async fn test_server_client_bridge() {
        let mut server = new_quic_server(
            SocketAddr::from_str("127.0.0.1:0").unwrap(),
            include_str!(".././test_cert.pem"),
            include_str!(".././test_key.pem"),
        )
        .await
        .unwrap();

        let mut client_conn = new_quic_connection(
            server.local_addr().unwrap(),
            include_str!(".././test_cert.pem"),
            "localhost",
        )
        .await
        .unwrap();
        assert!(client_conn.keep_alive(true).is_ok());

        tokio::spawn(async move {
            let conn_result = server.accept().await;
            assert!(conn_result.is_some());

            let mut conn = conn_result.unwrap();

            let bdstream_result = conn.accept_bidirectional_stream().await;
            assert!(bdstream_result.is_ok());

            let bdstream_option = bdstream_result.unwrap();
            assert!(bdstream_option.is_some());

            let mut bdstream = bdstream_option.unwrap();

            let recv_data_result = bdstream.receive().await;
            assert!(recv_data_result.is_ok());

            let recv_data_option = recv_data_result.unwrap();
            assert!(recv_data_option.is_some());

            let client_cmd_res = ProtoCommand::serialize(recv_data_option.unwrap());
            assert!(client_cmd_res.is_some());

            assert!(bdstream.send(ProtoCommand::ACK.deserialize()).await.is_ok());

            conn.close(6u32.into());
        });

        let bdstream_result = client_conn.open_bidirectional_stream().await;
        assert!(bdstream_result.is_ok());
        let mut bdstream = bdstream_result.unwrap();

        assert!(bdstream
            .send(ProtoCommand::ACK.deserialize())
            .await
            .is_ok());

        client_conn.close(6u32.into());
    }

    #[tokio::test]
    async fn test_resolve_and_connect_via_hostname() {
        let server = new_quic_server(
            SocketAddr::from_str("127.0.0.1:0").unwrap(),
            include_str!(".././test_cert.pem"),
            include_str!(".././test_key.pem"),
        )
        .await
        .unwrap();

        let port = server.local_addr().unwrap().port();
        let (_host, _p, addr) = sirang::quic::resolve_host_port(&format!("localhost:{port}"))
            .await
            .unwrap();

        let conn = new_quic_connection(addr, include_str!(".././test_cert.pem"), "localhost").await;
        assert!(conn.is_ok());
    }
}
