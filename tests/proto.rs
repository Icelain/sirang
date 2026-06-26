//! Integration-style coverage for the control protocol.

use bytes::Bytes;
use sirang::common::proto::ProtoCommand;
use std::net::SocketAddr;
use std::str::FromStr;

#[test]
fn all_commands_roundtrip() {
    let cases = vec![
        ProtoCommand::CLOSED,
        ProtoCommand::ACK,
        ProtoCommand::REGISTERED,
        ProtoCommand::CONNECTED(SocketAddr::from_str("[::1]:9").unwrap()),
        ProtoCommand::CONNECTED(SocketAddr::from_str("10.0.0.1:4433").unwrap()),
        ProtoCommand::REGISTER {
            group: "g1".into(),
            authorization: None,
        },
        ProtoCommand::REGISTER {
            group: "g2".into(),
            authorization: Some("Bearer tok".into()),
        },
        ProtoCommand::RegisterErr("nope".into()),
    ];
    for cmd in cases {
        let bytes = cmd.deserialize();
        let back = ProtoCommand::serialize(bytes).expect("serialize");
        assert_eq!(back, cmd);
    }
}

#[test]
fn rejects_garbage() {
    for raw in [b"" as &[u8], b" ", b"FOO", b"REGISTER", b"CONNECTED x"] {
        assert!(ProtoCommand::serialize(Bytes::copy_from_slice(raw)).is_none());
    }
}
