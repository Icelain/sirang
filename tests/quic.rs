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
        )
        .await;
        assert_eq!(new_conn_result.is_ok(), true);
    }

    #[tokio::test]
    async fn test_create_new_quic_server() {
        let socket_addr_result = SocketAddr::from_str("127.0.0.1:0");
        assert_eq!(socket_addr_result.is_ok(), true);
        let socket_addr = socket_addr_result.unwrap();

        let new_server_result = new_quic_server(
            socket_addr,
            include_str!(".././test_cert.pem"),
            include_str!(".././test_key.pem"),
        )
        .await;
        assert_eq!(new_server_result.is_ok(), true);
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
        )
        .await
        .unwrap();
        assert_eq!(client_conn.keep_alive(true).is_ok(), true);

        tokio::spawn(async move {
            let conn_result = server.accept().await;
            assert_eq!(conn_result.is_some(), true);

            let mut conn = conn_result.unwrap();

            let bdstream_result = conn.accept_bidirectional_stream().await;
            assert_eq!(bdstream_result.is_ok(), true);

            let bdstream_option = bdstream_result.unwrap();
            assert_eq!(bdstream_option.is_some(), true);

            let mut bdstream = bdstream_option.unwrap();

            let recv_data_result = bdstream.receive().await;
            assert_eq!(recv_data_result.is_ok(), true);

            let recv_data_option = recv_data_result.unwrap();
            assert_eq!(recv_data_option.is_some(), true);

            let client_cmd_res = ProtoCommand::serialize(recv_data_option.unwrap());
            assert_eq!(client_cmd_res.is_some(), true);

            assert_eq!(
                bdstream.send(ProtoCommand::ACK.deserialize()).await.is_ok(),
                true
            );

            conn.close(6u32.into());
        });

        let bdstream_result = client_conn.open_bidirectional_stream().await;
        assert_eq!(bdstream_result.is_ok(), true);
        let mut bdstream = bdstream_result.unwrap();

        assert_eq!(
            bdstream.send(ProtoCommand::ACK.deserialize()).await.is_ok(),
            true
        );

        client_conn.close(6u32.into());
    }
}
