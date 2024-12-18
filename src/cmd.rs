use crate::{errors, local, remote};
use std::{net::SocketAddr, path::PathBuf};

use clap::{arg, command, value_parser, ArgMatches, Command};

pub async fn execute() {
    let matches = command!()
        .subcommand(
            Command::new("remote")
                .about("Starts a remote ended server")
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

                        -a --addr <ADDRESS> "Address to run the remote server on"

                    )
                    .required(false)
                    .value_parser(value_parser!(SocketAddr)),
                )
        )
        .subcommand(
            Command::new("local")
                .about("Starts the local tcp forwarding server")
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

        .get_matches();

    if let Err(e) = handle_matches(matches).await {
        eprintln!("Error occurred: {}", e);
    }
}

async fn handle_matches(
    arg_matches: ArgMatches,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    if let Some(remote_matches) = arg_matches.subcommand_matches("remote") {
        let mut remote_config = remote::config::RemoteConfig::default();

        if let Some(forward_addr) = remote_matches.get_one::<SocketAddr>("forwardaddr") {
            remote_config.forward_address = *forward_addr;
        }

        if let Some(addr) = remote_matches.get_one::<SocketAddr>("addr") {
            remote_config.address = *addr;
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
                std::fs::read_to_string(tls_key_file.to_str().unwrap().to_string())?;
        }

        remote::start_remote(remote_config).await?;
    }

    if let Some(local_matches) = arg_matches.subcommand_matches("local") {
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
                std::fs::read_to_string(tls_cert_file.to_str().unwrap().to_string())?;
        }
        local::start_local(local_config).await?;
    }

    Ok(())
}
