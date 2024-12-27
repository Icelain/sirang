pub const DEFAULT_BUFSIZE: usize = 1024 * 32;

#[derive(PartialEq, Clone)]
pub enum TunnelType {
    Forward,
    Reverse,
}

pub mod proto {
    use core::str;
    use std::{net::SocketAddr, str::FromStr};

    use bytes::Bytes;

    #[derive(Debug, PartialEq)]
    pub enum ProtoCommand {
        CONNECTED(SocketAddr),
        CLOSED,
        ACK,
    }

    impl ProtoCommand {
        pub fn deserialize(&self) -> Bytes {
            match self {
                &ProtoCommand::CONNECTED(socket_addr) => {
                    return Bytes::copy_from_slice(
                        [b"CONNECTED ", socket_addr.to_string().as_bytes()]
                            .concat()
                            .as_slice(),
                    );
                }
                &ProtoCommand::CLOSED => {
                    return Bytes::from_static(b"CLOSED");
                }
                &ProtoCommand::ACK => {
                    return Bytes::from_static(b"ACK");
                }
            }
        }

        pub fn serialize(data: Bytes) -> Option<Self> {
            let mut iter = data.split(|byte| *byte == b" "[0]);
            if let Some(cmd) = iter.next() {
                match cmd {
                    b"CONNECTED" => {
                        if let Some(addr_bytes) = iter.next() {
                            if let Ok(addr_bytes_str) = &str::from_utf8(addr_bytes) {
                                if let Ok(address) = SocketAddr::from_str(addr_bytes_str) {
                                    return Some(ProtoCommand::CONNECTED(address));
                                }
                            }
                        }

                        return None;
                    }
                    b"CLOSED" => {
                        return Some(ProtoCommand::CLOSED);
                    }
                    b"ACK" => {
                        return Some(ProtoCommand::ACK);
                    }
                    _ => {}
                }
            }

            None
        }
    }

    #[cfg(test)]
    mod tests {

        use std::{net::SocketAddr, str::FromStr};

        use bytes::Bytes;

        use super::ProtoCommand;

        #[test]
        fn test_serialize() {
            assert_eq!(
                ProtoCommand::serialize(Bytes::from_static(b"CLOSED")).unwrap(),
                ProtoCommand::CLOSED
            );

            assert_eq!(
                ProtoCommand::serialize(Bytes::from_static(b"ACK")).unwrap(),
                ProtoCommand::ACK
            );

            assert_eq!(
                ProtoCommand::serialize(Bytes::from_static(b"CONNECTED 127.0.0.1:5050")).unwrap(),
                ProtoCommand::CONNECTED(SocketAddr::from_str("127.0.0.1:5050").unwrap())
            );
        }

        #[test]
        fn test_deserialize() {
            let closed_cmd = ProtoCommand::CLOSED;
            let ack_cmd = ProtoCommand::ACK;
            let connected_cmd =
                ProtoCommand::CONNECTED(SocketAddr::from_str("127.0.0.1:5050").unwrap());

            assert_eq!(closed_cmd.deserialize(), Bytes::from_static(b"CLOSED"));
            assert_eq!(ack_cmd.deserialize(), Bytes::from_static(b"ACK"));
            assert_eq!(
                connected_cmd.deserialize(),
                Bytes::from_static(b"CONNECTED 127.0.0.1:5050")
            );
        }
    }
}
