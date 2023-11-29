use clap::Parser;

use super::Command;

#[derive(Parser, Debug)]
pub struct PingArgs {
    #[arg(short, long)]
    message: String,
}

pub struct PingCommand;

impl Command for PingCommand {
    fn execute(&self, args: &Vec<String>) {
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