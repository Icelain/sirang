pub const DEFAULT_BUFSIZE: usize = 1024 * 32;

#[derive(PartialEq)]
pub enum TunnelType {
    Forward,
    Reverse,
}

pub mod proto {
    use core::str;
    use std::{net::SocketAddr, str::FromStr};

    use bytes::Bytes;

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
}
