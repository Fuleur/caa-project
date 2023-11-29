use crate::commands::{exit::ExitCommand, help::HelpCommand, ping::PingCommand, Command};
use colored::Colorize;
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    io::{self, Write},
};

mod commands;

lazy_static! {
    static ref COMMANDS: HashMap<&'static str, Box<dyn Command + Sync>> = {
        let mut map: HashMap<&'static str, Box<dyn Command + Sync>> = HashMap::new();
        map.insert("help", Box::new(HelpCommand));
        map.insert("exit", Box::new(ExitCommand));
        map.insert("ping", Box::new(PingCommand));

        map
    };
}

fn main() {
    println!("Welcome to {} (Totally Secure File Storage) !", "TSFS".cyan());
    println!("Type {} for the command list", "help".green());

    loop {
        print!("cmd: ");
        io::stdout().flush().unwrap();
        let mut line = String::new();

        io::stdin().read_line(&mut line).unwrap();
        let args = commands::parse(&line);

        if let Some(cmd) = COMMANDS.get(args.get(0).unwrap().as_str()) {
            cmd.execute(&args);
        } else {
            println!("{} Unknown command", "[Error]".red());
        }
    }
}
