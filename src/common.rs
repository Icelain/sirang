pub const DEFAULT_BUFSIZE: usize = 1024 * 32;

#[derive(Debug, PartialEq, Clone)]
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
        /// Local client registers into a tunnel group (reverst-style).
        /// Optional second field is a full Authorization header value (e.g. "Basic xxx").
        REGISTER { group: String, authorization: Option<String> },
        REGISTERED,
        RegisterErr(String),
    }

    impl ProtoCommand {
        pub fn deserialize(&self) -> Bytes {
            match self {
                ProtoCommand::CONNECTED(socket_addr) => Bytes::copy_from_slice(
                    [b"CONNECTED ", socket_addr.to_string().as_bytes()]
                        .concat()
                        .as_slice(),
                ),
                ProtoCommand::CLOSED => Bytes::from_static(b"CLOSED"),
                ProtoCommand::ACK => Bytes::from_static(b"ACK"),
                ProtoCommand::REGISTER {
                    group,
                    authorization,
                } => {
                    let mut s = format!("REGISTER {group}");
                    if let Some(auth) = authorization {
                        s.push(' ');
                        s.push_str(auth);
                    }
                    Bytes::copy_from_slice(s.as_bytes())
                }
                ProtoCommand::REGISTERED => Bytes::from_static(b"REGISTERED"),
                ProtoCommand::RegisterErr(msg) => {
                    Bytes::copy_from_slice(format!("REGISTER_ERR {msg}").as_bytes())
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
                    b"REGISTERED" => {
                        return Some(ProtoCommand::REGISTERED);
                    }
                    b"REGISTER_ERR" => {
                        let msg = iter
                            .next()
                            .and_then(|b| str::from_utf8(b).ok())
                            .unwrap_or("error")
                            .to_string();
                        // include remainder of message
                        let rest: Vec<&str> = iter
                            .filter_map(|b| str::from_utf8(b).ok())
                            .collect();
                        let msg = if rest.is_empty() {
                            msg
                        } else {
                            format!("{msg} {}", rest.join(" "))
                        };
                        return Some(ProtoCommand::RegisterErr(msg));
                    }
                    b"REGISTER" => {
                        let group = iter
                            .next()
                            .and_then(|b| str::from_utf8(b).ok())?
                            .to_string();
                        let scheme = iter.next().and_then(|b| str::from_utf8(b).ok());
                        let payload = iter.next().and_then(|b| str::from_utf8(b).ok());
                        let authorization = match (scheme, payload) {
                            (Some(s), Some(p)) => Some(format!("{s} {p}")),
                            _ => None,
                        };
                        return Some(ProtoCommand::REGISTER { group, authorization });
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

        #[test]
        fn test_register_roundtrip() {
            let cmd = ProtoCommand::REGISTER {
                group: "localhost".into(),
                authorization: None,
            };
            assert_eq!(
                ProtoCommand::serialize(cmd.deserialize()).unwrap(),
                cmd
            );

            let cmd = ProtoCommand::REGISTER {
                group: "g".into(),
                authorization: Some("Basic dXNlcjpwYXNz".into()),
            };
            assert_eq!(
                ProtoCommand::serialize(cmd.deserialize()).unwrap(),
                cmd
            );
        }

        #[test]
        fn test_registered_and_err_roundtrip() {
            assert_eq!(
                ProtoCommand::serialize(ProtoCommand::REGISTERED.deserialize()).unwrap(),
                ProtoCommand::REGISTERED
            );
            let err = ProtoCommand::RegisterErr("unauthorized".into());
            assert_eq!(
                ProtoCommand::serialize(err.deserialize()).unwrap(),
                ProtoCommand::RegisterErr("unauthorized".into())
            );
            let err_multi = ProtoCommand::serialize(Bytes::from_static(
                b"REGISTER_ERR bad gateway no clients",
            ))
            .unwrap();
            assert_eq!(
                err_multi,
                ProtoCommand::RegisterErr("bad gateway no clients".into())
            );
        }

        #[test]
        fn test_serialize_invalid() {
            assert!(ProtoCommand::serialize(Bytes::from_static(b"NOPE")).is_none());
            assert!(ProtoCommand::serialize(Bytes::from_static(b"CONNECTED")).is_none());
            assert!(ProtoCommand::serialize(Bytes::from_static(b"CONNECTED not-an-addr")).is_none());
            assert!(ProtoCommand::serialize(Bytes::new()).is_none());
        }
    }

    #[cfg(test)]
    mod tunnel_type_tests {
        use super::super::{TunnelType, DEFAULT_BUFSIZE};

        #[test]
        fn test_defaults() {
            assert_eq!(DEFAULT_BUFSIZE, 1024 * 32);
            assert_eq!(TunnelType::Forward, TunnelType::Forward);
            assert_ne!(TunnelType::Forward, TunnelType::Reverse);
        }
    }
}
