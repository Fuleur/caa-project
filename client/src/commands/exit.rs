use crate::{TSFSContext, commands::logout::LogoutCommand};

use super::Command;

pub struct ExitCommand;

impl Command for ExitCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        LogoutCommand.execute(&vec![], ctx);

        println!("Goodbye, world!");
        std::process::exit(0);
    }

    fn description(&self) -> String {
        "Quit the program".into()
    }
}
