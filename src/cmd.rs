use crate::{common::TunnelType, errors, local, remote};
use std::{net::SocketAddr, path::PathBuf, process::exit};

use clap::{arg, command, value_parser, ArgAction, ArgMatches, Command};

pub async fn execute() {
    let matches = command!()
        .subcommand(
            Command::new("forward")
            .arg_required_else_help(true)
            .about("Starts a forward tunnel instance")
                .subcommand(
                    Command::new("remote")
                        .about("Starts a remote ended server for the forward tunnel instance")
                        .arg(
                            arg!(

                                -k --key <PATH> "Path to the tls key file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(

                                -c --cert <PATH> "Path to the tls certificate file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )

                        .arg(
                            arg!(

                                -f --forwardaddr <ADDRESS> "Remote Tcp address to forward the tunnel to"

                            )
                            .required(true)
                            .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(

                                -q --quicaddr <ADDRESS> "Address to run the remote quic server on"

                            )
                            .required(false)
                            .value_parser(value_parser!(SocketAddr)),
                        )
               )
                .subcommand(
                    Command::new("local")
                        .about("Starts the local tcp forwarding server for the forward tunnel instance")
                        .arg(
                            arg!(

                                -c --cert <PATH> "Path to the tls certificate file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(

                                -l --localaddr <ADDRESS> "Address to run the local tcp forwarding server on"

                            )
                            .required(false)
                            .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(

                                -r --remoteaddr <ADDRESS> "Address of the remote quic instance to connect to"

                            )
                            .required(true)
                            .value_parser(value_parser!(SocketAddr)),
                        )

                )
                 .arg(
                    arg!(

                        -d --debug "Turns on debug logging"

                    )
                    .required(false)
                    .action(ArgAction::SetTrue)
                )
                .arg(
                    arg!(

                        -b --buffersize [SIZE] "Sets the buffer size"

                    )
                    .required(false)
                    .value_parser(value_parser!(usize))
                )
        )
         .subcommand(
            Command::new("reverse")
            .arg_required_else_help(true)
            .about("Starts a reverse tunnel instance")
                .subcommand(
                    Command::new("remote")
                        .about("Starts a remote ended server for the reverse tunnel instance")
                        .arg(
                            arg!(

                                -k --key <PATH> "Path to the tls key file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(

                                -c --cert <PATH> "Path to the tls certificate file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )

                        .arg(
                            arg!(

                                -q --quicaddr <ADDRESS> "Address to run the remote quic server on"

                            )
                            .required(false)
                            .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(

                                -t --tcpaddr <ADDRESS> "Address to run the remote tcp server on"

                            )
                            .required(false)
                            .value_parser(value_parser!(SocketAddr)),
                        )
               )
                .subcommand(
                    Command::new("local")
                        .about("Starts the local tcp forwarding server for the reverse tunnel instance")
                        .arg(
                            arg!(

                                -c --cert <PATH> "Path to the tls certificate file"

                            )
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                        )
                        .arg(
                            arg!(

                                -l --localaddr <ADDRESS> "Address to run the local tcp forwarding server on"

                            )
                            .required(true)
                            .value_parser(value_parser!(SocketAddr)),
                        )
                        .arg(
                            arg!(

                                -r --remoteaddr <ADDRESS> "Address of the remote quic instance to connect to"

                            )
                            .required(true)
                            .value_parser(value_parser!(SocketAddr)),
                        )

                )
                 .arg(
                    arg!(

                        -d --debug "Turns on debug logging"

                    )
                    .required(false)
                    .action(ArgAction::SetTrue)
                )
                .arg(
                    arg!(

                        -b --buffersize [SIZE] "Sets the buffer size"

                    )
                    .required(false)
                    .value_parser(value_parser!(usize))
                )        
        )
        .arg_required_else_help(true)
        .get_matches();

    if let Err(e) = handle_matches(matches).await {
        log::error!("Error occured: {e}");
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
                None => {exit(0);}

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
            if let Some(tcp_addr) = remote_matches.get_one::<SocketAddr>("tcpaddr") {
                remote_config.tcp_reverse_address = Some(*tcp_addr);
            }
        } else if let Some(forward_addr) = remote_matches.get_one::<SocketAddr>("forwardaddr") {
            remote_config.tcp_forward_address = Some(*forward_addr);
        }

        if let Some(addr) = remote_matches.get_one::<SocketAddr>("quicaddr") {
            remote_config.quic_address = *addr;
        }

        if let Some(tls_cert_file) = remote_matches.get_one::<PathBuf>("cert") {
            if !tls_cert_file.exists() {
                return Err(Box::new(errors::GenericError(
                    "Tls certificate file doesn't exist".to_string(),
                )));
            }

            remote_config.tls_cert = std::fs::read_to_string(tls_cert_file.to_str().unwrap())?;
        }
        if let Some(tls_key_file) = remote_matches.get_one::<PathBuf>("key") {
            if !tls_key_file.exists() {
                return Err(Box::new(errors::GenericError(
                    "Tls key file doesn't exist".to_string(),
                )));
            }

            remote_config.tls_key =
                std::fs::read_to_string(tls_key_file.to_str().unwrap())?;
        }

        if let Some(buffer_size) = buffersize {
            remote_config.buffer_size = *buffer_size;
        }

        remote::start_remote(remote_config).await?;
    }

    else if let Some(local_matches) = cmd_matches.subcommand_matches("local") {
        let mut local_config = local::config::LocalConfig::default();

        if let Some(local_addr) = local_matches.get_one::<SocketAddr>("localaddr") {
            local_config.local_tcp_server_addr = *local_addr;
        }
        if let Some(remote_addr) = local_matches.get_one::<SocketAddr>("remoteaddr") {
            local_config.remote_quic_server_addr = *remote_addr;
        }
        if let Some(tls_cert_file) = local_matches.get_one::<PathBuf>("cert") {
            if !tls_cert_file.exists() {
                return Err(Box::new(errors::GenericError(
                    "Tls certificate file doesn't exist".to_string(),
                )));
            }

            local_config.tls_cert =
                std::fs::read_to_string(tls_cert_file.to_str().unwrap())?;
        }

        if let Some(buffer_size) = buffersize {
            local_config.buffer_size = *buffer_size;
        }

        local_config.tunnel_type = tunnel_type;

        local::start_local(local_config).await?;
    }

    Ok(())
}
