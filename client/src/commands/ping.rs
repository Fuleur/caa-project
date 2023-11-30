use clap::Parser;

use crate::TSFSContext;

use super::Command;

/// Send a ping message
#[derive(Parser, Debug)]
pub struct PingArgs {
    /// Message to pong
    #[arg(short, long)]
    message: String,
}

pub struct PingCommand;

impl Command for PingCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match PingArgs::try_parse_from(args) {
            Ok(args) => {
                println!("{}", args.message);
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "Ping test command".into()
    }
}
