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
        /// Remote asks the local client for a connect password.
        AuthRequired,
        /// Local supplies the connect password (may contain spaces in the remainder).
        Auth(String),
        AuthOk,
        AuthErr(String),
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
                ProtoCommand::AuthRequired => Bytes::from_static(b"AUTH_REQUIRED"),
                ProtoCommand::Auth(password) => {
                    Bytes::copy_from_slice(format!("AUTH {password}").as_bytes())
                }
                ProtoCommand::AuthOk => Bytes::from_static(b"AUTH_OK"),
                ProtoCommand::AuthErr(msg) => {
                    Bytes::copy_from_slice(format!("AUTH_ERR {msg}").as_bytes())
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
                    b"AUTH_REQUIRED" => {
                        return Some(ProtoCommand::AuthRequired);
                    }
                    b"AUTH_OK" => {
                        return Some(ProtoCommand::AuthOk);
                    }
                    b"AUTH_ERR" => {
                        let msg = join_rest(&mut iter, "error");
                        return Some(ProtoCommand::AuthErr(msg));
                    }
                    b"AUTH" => {
                        let password = join_rest(&mut iter, "");
                        if password.is_empty() {
                            return None;
                        }
                        return Some(ProtoCommand::Auth(password));
                    }
                    b"REGISTER_ERR" => {
                        let msg = join_rest(&mut iter, "error");
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

    fn join_rest<'a, I>(iter: &mut I, default: &str) -> String
    where
        I: Iterator<Item = &'a [u8]>,
    {
        let parts: Vec<&str> = iter.filter_map(|b| str::from_utf8(b).ok()).collect();
        if parts.is_empty() {
            default.to_string()
        } else {
            parts.join(" ")
        }
    }

    /// Constant-time-ish password compare (length leak only).
    pub fn passwords_equal(expected: &str, provided: &str) -> bool {
        let a = expected.as_bytes();
        let b = provided.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
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

        #[test]
        fn test_auth_commands_roundtrip() {
            for cmd in [
                ProtoCommand::AuthRequired,
                ProtoCommand::AuthOk,
                ProtoCommand::Auth("s3cret".into()),
                ProtoCommand::Auth("pass with spaces".into()),
                ProtoCommand::AuthErr("bad password".into()),
            ] {
                assert_eq!(ProtoCommand::serialize(cmd.deserialize()).unwrap(), cmd);
            }
        }

        #[test]
        fn test_passwords_equal() {
            assert!(super::passwords_equal("abc", "abc"));
            assert!(!super::passwords_equal("abc", "abd"));
            assert!(!super::passwords_equal("abc", "ab"));
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
