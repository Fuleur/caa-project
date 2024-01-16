use clap::Parser;
use colored::Colorize;

use crate::{log, Config, TSFSContext};

use super::Command;

/// Set context values
#[derive(Parser, Debug)]
struct SetArgs {
    /// Show current context
    #[arg(short, long)]
    show: bool,

    /// Set endpoint_url
    #[arg(short, long)]
    endpoint_url: Option<String>,

    /// Set endpoint_port
    #[arg(short, long)]
    port: Option<u32>,

    /// Set accept_invalid_cert. Use only in dev environnement !
    #[arg(short, long)]
    accept_invalid_cert: Option<bool>,
}

pub struct SetCommand;

impl Command for SetCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match SetArgs::try_parse_from(args) {
            Ok(args) => {
                // Set endpoint_url
                if let Some(endpoint_url) = args.endpoint_url {
                    if ctx.session_token.is_some() {
                        log::error(&format!(
                            "Can't modify {} while logged on, must {} first",
                            "endpoint_url".green(),
                            "logout".green()
                        ));
                    } else {
                        ctx.endpoint_url = Some(endpoint_url);
                        println!("{} updated", "endpoint_url".green());
                    }
                }

                // Set endpoint_port
                if let Some(endpoint_port) = args.port {
                    if ctx.session_token.is_some() {
                        log::error(&format!(
                            "Can't modify {} while logged on, must {} first",
                            "endpoint_port".green(),
                            "logout".green()
                        ));
                    } else {
                        ctx.endpoint_port = endpoint_port;
                        println!("{} updated", "endpoint_port".green());
                    }
                }

                // Set accept_invalid_cert
                if let Some(accept_invalid_cert) = args.accept_invalid_cert {
                    ctx.accept_invalid_cert = accept_invalid_cert;
                    println!("{} updated", "accept_invalid_cert".green());
                }

                confy::store(
                    "tsfs_cli",
                    "settings",
                    Config {
                        endpoint_url: ctx.endpoint_url.clone(),
                        endpoint_port: ctx.endpoint_port,
                        accept_invalid_cert: ctx.accept_invalid_cert,
                        local_folder: ctx.local_folder.clone(),
                    },
                )
                .unwrap();

                // Show current context
                if args.show {
                    println!("{:?}", ctx);
                }
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "Set context values".into()
    }
}
