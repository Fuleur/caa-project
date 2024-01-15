use base64::prelude::*;
use clap::Parser;
use colored::Colorize;

use crate::{log, models::FileWithoutDataWithKeyring, TSFSContext};

use super::Command;

/// List the content of the current folder
#[derive(Parser, Debug)]
pub struct LsArgs {
    // path: Option<String>,
}

pub struct LsCommand;

impl Command for LsCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match LsArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(keyring_tree) = &ctx.keyring_tree {
                    // TODO: Request new Keyring Tree to the Server

                    let mut current_folder = None;
                    if let Some(current_folder_id) = &ctx.current_folder.last() {
                        current_folder = keyring_tree.get_file(current_folder_id);
                    };

                    let current_keyring = if let Some(folder) = &current_folder {
                        folder.file.keyring.as_ref().unwrap()
                    } else {
                        keyring_tree
                    };

                    println!("{} {}", "----".cyan(), ctx.get_path().cyan());

                    for key in current_keyring.keys.iter() {
                        // If not in root, need to decrypt using the folder symmetric key
                        // Root keyring is already decrypted
                        /*let mut name = key.file.name;

                        if let Some(current_folder) = current_folder {
                            let enc_name = BASE64_STANDARD.decode(&key.file.name);
                            let no = &current_folder.key[0..96];
                        }*/

                        if key.file.is_folder() {
                            println!("{}", key.file.name.cyan());
                        } else {
                            // Print file size, date, etc...
                            println!("{}", key.file.name);
                        }
                    }
                } else {
                    log::error("Missing Keyring Tree, not logged ?");
                }
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "List the content of the current folder".into()
    }
}
