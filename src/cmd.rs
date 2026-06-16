use crate::{common::TunnelType, errors, local, quic, remote};
use std::{net::SocketAddr, path::PathBuf, process::exit};

use clap::{arg, command, value_parser, ArgAction, ArgMatches, Command};

pub async fn execute() {
    let matches = command!()
        .about("A forward and reverse TCP tunnel over QUIC")
        .subcommand(
            Command::new("forward")
                .arg_required_else_help(true)
                .about("Forward tunnel: local TCP → remote QUIC → remote TCP target")
                .subcommand(
                    Command::new("remote")
                        .about("Run the remote side of a forward tunnel")
                        .arg(
                            arg!(-k --key <PATH> "Path to the TLS private key")
                                .required(true)
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(-c --cert <PATH> "Path to the TLS certificate")
                                .required(true)
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(-f --forward <ADDRESS> "TCP address to forward traffic to")
                                .required(true)
                                .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(-q --quic <ADDRESS> "QUIC listen address")
                                .required(false)
                                .default_value("0.0.0.0:4433")
                                .value_parser(value_parser!(SocketAddr)),
                        ),
                )
                .subcommand(
                    Command::new("local")
                        .about("Run the local side of a forward tunnel")
                        .arg(
                            arg!(-r --remote <REMOTE> "Remote sirang instance as host:port (DNS names supported)")
                                .required(true),
                        )
                        .arg(
                            arg!(-l --local <ADDRESS> "Local TCP listen address")
                                .required(false)
                                .default_value("127.0.0.1:8080")
                                .value_parser(value_parser!(SocketAddr)),
                        ),
                )
                .arg(
                    arg!(-d --debug "Enable debug logging")
                        .required(false)
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-b --buffersize [SIZE] "Buffer size in bytes")
                        .required(false)
                        .value_parser(value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("reverse")
                .arg_required_else_help(true)
                .about("Reverse tunnel: remote TCP → remote QUIC → local TCP target")
                .subcommand(
                    Command::new("remote")
                        .about("Run the remote side of a reverse tunnel")
                        .arg(
                            arg!(-k --key <PATH> "Path to the TLS private key")
                                .required(true)
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(-c --cert <PATH> "Path to the TLS certificate")
                                .required(true)
                                .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(-q --quic <ADDRESS> "QUIC listen address")
                                .required(false)
                                .default_value("0.0.0.0:4433")
                                .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(-t --tcp <ADDRESS> "Preferred TCP listen address for clients")
                                .required(false)
                                .default_value("0.0.0.0:5000")
                                .value_parser(value_parser!(SocketAddr)),
                        ),
                )
                .subcommand(
                    Command::new("local")
                        .about("Run the local side of a reverse tunnel")
                        .arg(
                            arg!(-r --remote <REMOTE> "Remote sirang instance as host:port (DNS names supported)")
                                .required(true),
                        )
                        .arg(
                            arg!(-l --local <ADDRESS> "Local TCP address to tunnel")
                                .required(true)
                                .value_parser(value_parser!(SocketAddr)),
                        ),
                )
                .arg(
                    arg!(-d --debug "Enable debug logging")
                        .required(false)
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    arg!(-b --buffersize [SIZE] "Buffer size in bytes")
                        .required(false)
                        .value_parser(value_parser!(usize)),
                ),
        )
        .arg_required_else_help(true)
        .get_matches();

    if let Err(e) = handle_matches(matches).await {
        log::error!("Error occurred: {e}");
        exit(1);
    }
}

async fn handle_matches(
    arg_matches: ArgMatches,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut tunnel_type = TunnelType::Forward;

    let cmd_matches = match arg_matches.subcommand_matches("forward") {
        Some(m) => m,
        None => {
            tunnel_type = TunnelType::Reverse;
            match arg_matches.subcommand_matches("reverse") {
                Some(m) => m,
                None => {
                    exit(0);
                }
            }
        }
    };

    let mut log_builder = colog::default_builder();

    if !cmd_matches.get_flag("debug") {
        log_builder.filter_level(log::LevelFilter::Info);
    } else {
        log_builder.filter_level(log::LevelFilter::Trace);
    }

    log_builder.init();

    let buffersize = cmd_matches.get_one::<usize>("buffersize");

    if let Some(remote_matches) = cmd_matches.subcommand_matches("remote") {
        let mut remote_config = remote::config::RemoteConfig::new(&tunnel_type);

        if remote_config.tunnel_type == TunnelType::Reverse {
            if let Some(tcp_addr) = remote_matches.get_one::<SocketAddr>("tcp") {
                remote_config.tcp_reverse_address = Some(*tcp_addr);
            }
        } else if let Some(forward_addr) = remote_matches.get_one::<SocketAddr>("forward") {
            remote_config.tcp_forward_address = Some(*forward_addr);
        }

        if let Some(addr) = remote_matches.get_one::<SocketAddr>("quic") {
            remote_config.quic_address = *addr;
        }

        if let Some(tls_cert_file) = remote_matches.get_one::<PathBuf>("cert") {
            if !tls_cert_file.exists() {
                return Err(Box::new(errors::GenericError(
                    "TLS certificate file doesn't exist".to_string(),
                )));
            }

            remote_config.tls_cert = std::fs::read_to_string(tls_cert_file)?;
        }
        if let Some(tls_key_file) = remote_matches.get_one::<PathBuf>("key") {
            if !tls_key_file.exists() {
                return Err(Box::new(errors::GenericError(
                    "TLS key file doesn't exist".to_string(),
                )));
            }

            remote_config.tls_key = std::fs::read_to_string(tls_key_file)?;
        }

        if let Some(buffer_size) = buffersize {
            remote_config.buffer_size = *buffer_size;
        }

        remote::start_remote(remote_config).await?;
    } else if let Some(local_matches) = cmd_matches.subcommand_matches("local") {
        let mut local_config = local::config::LocalConfig::default();

        if let Some(local_addr) = local_matches.get_one::<SocketAddr>("local") {
            local_config.local_tcp_server_addr = *local_addr;
        }

        let remote_host_port = local_matches
            .get_one::<String>("remote")
            .ok_or_else(|| {
                Box::new(errors::GenericError(
                    "Remote address is required".to_string(),
                )) as Box<dyn std::error::Error + Send + Sync + 'static>
            })?;

        let (host, _port, addr) = quic::resolve_host_port(remote_host_port).await?;
        local_config.remote_host = host;
        local_config.remote_quic_server_addr = addr;

        // Certificate is fetched automatically from the remote on first connect.
        local_config.tls_cert = String::new();

        if let Some(buffer_size) = buffersize {
            local_config.buffer_size = *buffer_size;
        }

        local_config.tunnel_type = tunnel_type;

        local::start_local(local_config).await?;
    }

    Ok(())
}
