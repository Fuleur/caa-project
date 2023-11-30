use crate::commands::{
    exit::ExitCommand, help::HelpCommand, ping::PingCommand, set::SetCommand, Command, login::LoginCommand, register::RegisterCommand, logout::LogoutCommand,
};
use colored::Colorize;
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    io::{self, Write},
};

mod commands;
mod log;

// Initialize static `COMMANDS` HashMap
lazy_static! {
    static ref COMMANDS: HashMap<&'static str, Box<dyn Command + Sync>> = {
        let mut map: HashMap<&'static str, Box<dyn Command + Sync>> = HashMap::new();
        map.insert("help", Box::new(HelpCommand));
        map.insert("exit", Box::new(ExitCommand));
        map.insert("ping", Box::new(PingCommand));
        map.insert("set", Box::new(SetCommand));
        map.insert("login", Box::new(LoginCommand));
        map.insert("logout", Box::new(LogoutCommand));
        map.insert("register", Box::new(RegisterCommand));

        map
    };
}

fn main() {
    println!(
        "Welcome to {} (Totally Secure File Storage) !",
        "TSFS".cyan()
    );
    println!("Type {} for the command list", "help".green());

    let mut ctx = TSFSContext {
        endpoint_url: Some("tsfs.infrack.ch".into()),
        endpoint_port: 1315,
        session_token: Some(".".into()),
        username: Some("Fuler".into()),
    };

    if ctx.endpoint_url.is_none() {
        log::warning("endpoint_url not defined in context");
    }

    loop {
        print!(
            "{} {}> ",
            "[TSFS]".cyan(),
            if ctx.session_token.is_some() {
                format!(
                    "{}@{} ",
                    ctx.username.as_ref().unwrap().green(),
                    ctx.endpoint_url.as_ref().unwrap().cyan()
                )
            } else {
                "".to_string()
            }
        );
        io::stdout().flush().unwrap();
        let mut line = String::new();

        io::stdin().read_line(&mut line).unwrap();
        let args = commands::parse(&line);

        if let Some(cmd) = COMMANDS.get(args.get(0).unwrap().as_str()) {
            cmd.execute(&args, &mut ctx);
        } else {
            log::error(&format!("Unknown command '{}'", args.get(0).unwrap().red()));
        }
    }
}

/// Context of the TSFS Client
/// Some data are loaded from config file
/// Others are altered trough the program execution
#[derive(Debug)]
pub struct TSFSContext {
    endpoint_url: Option<String>,
    endpoint_port: u32,

    session_token: Option<String>,
    username: Option<String>,
}
