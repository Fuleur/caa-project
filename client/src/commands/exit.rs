use super::Command;

pub struct ExitCommand;

impl Command for ExitCommand {
    fn execute(&self, _args: &Vec<String>) {
        println!("Goodbye, world!");

        std::process::exit(0);
    }

    fn description(&self) -> String {
        "Quit the program".into()
    }
}