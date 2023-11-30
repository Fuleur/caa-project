use colored::Colorize;

use crate::{TSFSContext, COMMANDS};

use super::Command;

pub struct HelpCommand;

impl Command for HelpCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        println!("Command list:");

        for (name, cmd) in COMMANDS.iter() {
            println!("  {} - {}", name, cmd.description());
        }

        println!(
            "\nYou can use {} with every command to get the command related help !",
            "--help".green()
        );
    }

    fn description(&self) -> String {
        "Get command list".into()
    }
}
