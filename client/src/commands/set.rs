use clap::Parser;
use colored::Colorize;

use crate::{TSFSContext, log};

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
}

pub struct SetCommand;

impl Command for SetCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match SetArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(endpoint_url) = args.endpoint_url {
                    if ctx.session_token.is_some() {
                        log::error(&format!("Can't modify {} while logged on, must {} first", "endpoint_url".green(), "logout".green()));
                    } else {
                        ctx.endpoint_url = Some(endpoint_url);
                        println!("{} updated", "endpoint_url".green());
                    }
                }

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
