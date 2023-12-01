use crate::commands::{
    exit::ExitCommand, help::HelpCommand, login::LoginCommand, logout::LogoutCommand,
    ping::PingCommand, register::RegisterCommand, set::SetCommand, Command,
};
use colored::Colorize;
use lazy_static::lazy_static;
use opaque_ke::CipherSuite;
use serde::{Deserialize, Serialize};
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

    // Load config file
    let cfg = confy::load::<Config>("tsfs_cli", "settings").unwrap();

    // Construct Context from config
    let mut ctx = TSFSContext {
        endpoint_url: cfg.endpoint_url,
        endpoint_port: cfg.endpoint_port,
        session_token: None,
        username: None,
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
                if ctx.endpoint_url.is_some() {
                    format!("{} ", ctx.endpoint_url.as_ref().unwrap().red())
                } else {
                    "".to_string()
                }
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
#[derive(Clone, Debug)]
pub struct TSFSContext {
    endpoint_url: Option<String>,
    endpoint_port: u32,
    session_token: Option<String>,
    username: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    endpoint_url: Option<String>,
    endpoint_port: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint_url: None,
            endpoint_port: 1315,
        }
    }
}

pub struct DefaultCS;
impl CipherSuite for DefaultCS {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}
