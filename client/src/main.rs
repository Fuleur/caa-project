use crate::commands::{
    cd::CdCommand, change_password::ChangePasswordCommand, exit::ExitCommand, help::HelpCommand,
    login::LoginCommand, logout::LogoutCommand, ls::LsCommand, mkdir::MkdirCommand,
    ping::PingCommand, register::RegisterCommand, sessions::SessionsCommand, set::SetCommand,
    upload_file::UploadFileCommand, Command, rm::RmCommand, share::ShareCommand,
};
use argon2::Argon2;
use colored::Colorize;
use lazy_static::lazy_static;
use models::KeyringWithKeysAndFiles;
use opaque_ke::CipherSuite;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{self, Write},
    time::SystemTime,
};

mod commands;
mod crypto;
mod files;
mod log;
mod models;

// Initialize static `COMMANDS` HashMap
lazy_static! {
    static ref COMMANDS: HashMap<&'static str, Box<dyn Command + Sync + Send>> = {
        let mut map: HashMap<&'static str, Box<dyn Command + Sync + Send>> = HashMap::new();
        map.insert("help", Box::new(HelpCommand));
        map.insert("exit", Box::new(ExitCommand));
        map.insert("ping", Box::new(PingCommand));
        map.insert("set", Box::new(SetCommand));
        map.insert("login", Box::new(LoginCommand));
        map.insert("logout", Box::new(LogoutCommand));
        map.insert("register", Box::new(RegisterCommand));
        map.insert("sessions", Box::new(SessionsCommand));
        map.insert("change-password", Box::new(ChangePasswordCommand));
        map.insert("ls", Box::new(LsCommand));
        map.insert("cd", Box::new(CdCommand));
        map.insert("mkdir", Box::new(MkdirCommand));
        map.insert("upload", Box::new(UploadFileCommand));
        map.insert("rm", Box::new(RmCommand));
        map.insert("share", Box::new(ShareCommand));

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
    let cfg = match confy::load::<Config>("tsfs_cli", "settings") {
        Ok(config) => config,
        Err(_e) => {
            // Invalid config file, reset to default
            log::warning("Invalid config file, reseting to default");
            let cfg = Config::default();
            confy::store("tsfs_cli", "settings", &cfg).unwrap();

            cfg
        }
    };

    // Construct Context from config
    let mut ctx = TSFSContext {
        endpoint_url: cfg.endpoint_url,
        endpoint_port: cfg.endpoint_port,
        username: None,
        session_token: None,
        private_key: None,
        public_key: None,
        accept_invalid_cert: cfg.accept_invalid_cert,
        keyring_tree: None,
        current_folder: Vec::new(),
        last_keyring_update: SystemTime::now(),
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
                    "{}@{}{} ",
                    ctx.username.as_ref().unwrap().green(),
                    ctx.endpoint_url
                        .as_ref()
                        .unwrap()
                        .split("//")
                        .nth(1)
                        .unwrap()
                        .cyan(),
                    ctx.get_path().cyan(),
                )
            } else {
                if ctx.endpoint_url.is_some() {
                    format!(
                        "{} ",
                        ctx.endpoint_url
                            .as_ref()
                            .unwrap()
                            .split("//")
                            .nth(1)
                            .unwrap()
                            .red(),
                    )
                } else {
                    "".to_string()
                }
            }
        );
        io::stdout().flush().unwrap();
        let mut line = String::new();

        io::stdin().read_line(&mut line).unwrap();
        let args = commands::parse(&line);

        if args.len() > 0 {
            if let Some(cmd) = COMMANDS.get(args.get(0).unwrap().as_str()) {
                cmd.execute(&args, &mut ctx);
            } else {
                log::error(&format!("Unknown command '{}'", args.get(0).unwrap().red()));
            }
        } else {
            log::error("No command supplied");
        }
    }
}

/// Context of the TSFS Client
/// Some data are loaded from config file
/// Others are altered trough the program execution
#[derive(Clone, Debug)]
pub struct TSFSContext {
    /// Endpoint of the Server
    endpoint_url: Option<String>,
    /// Port used by the Server
    endpoint_port: u32,
    /// Username of current logged user
    username: Option<String>,
    /// Session token of the current Session
    session_token: Option<String>,
    /// Private key of the logged user
    private_key: Option<Vec<u8>>,
    /// Public key of the logged user
    public_key: Option<Vec<u8>>,
    /// Wheter or not to accept invalid certificates (like self-signed)
    /// Might be required on dev
    accept_invalid_cert: bool,
    /// The current Keyring Tree of the logged user
    keyring_tree: Option<KeyringWithKeysAndFiles>,
    /// The current location in the Tree
    current_folder: Vec<String>,
    /// Time of the last keyring update
    last_keyring_update: SystemTime,
}

impl TSFSContext {
    pub fn get_path(&self) -> String {
        let mut path = "/".to_string();

        for folder in &self.current_folder {
            path += &self
                .keyring_tree
                .as_ref()
                .unwrap()
                .get_file(folder)
                .unwrap()
                .file
                .name;
            path += "/";
        }

        path
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    endpoint_url: Option<String>,
    endpoint_port: u32,
    accept_invalid_cert: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint_url: None,
            endpoint_port: 8935,
            accept_invalid_cert: false,
        }
    }
}

pub struct DefaultCS;
impl CipherSuite for DefaultCS {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}
