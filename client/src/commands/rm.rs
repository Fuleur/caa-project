use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use clap::Parser;
use colored::Colorize;
use serde::Serialize;

use crate::{crypto, log, TSFSContext};

use super::{update_keyring, Command};

#[derive(Serialize)]
pub struct DeleteFileRequest {
    file_uid: String,
}

/// List the content of the current folder
#[derive(Parser, Debug)]
pub struct RmArgs {
    name: String,
}

pub struct RmCommand;

impl Command for RmCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match RmArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(keyring_tree) = &ctx.keyring_tree {
                    let mut current_folder = None;
                    if let Some(current_folder_id) = ctx.current_folder.last() {
                        current_folder = keyring_tree.get_file(current_folder_id);
                    };

                    let current_keyring = if let Some(folder) = &current_folder {
                        folder.file.keyring.as_ref().unwrap()
                    } else {
                        keyring_tree
                    };

                    if let Some(file) = current_keyring.get_file_by_name(&args.name) {
                        let client = reqwest::blocking::Client::builder()
                            .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                            .build()
                            .unwrap();

                        let res = client
                            .delete(format!(
                                "{}:{}/file/delete",
                                ctx.endpoint_url.as_ref().unwrap(),
                                ctx.endpoint_port
                            ))
                            .header(
                                "Authorization",
                                format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                            )
                            .json(&DeleteFileRequest {
                                file_uid: file.file.id,
                            })
                            .send();

                        match res {
                            Ok(res) => match res.error_for_status() {
                                Ok(_) => {
                                    log::info("File deleted !");

                                    update_keyring(ctx);
                                }

                                Err(e) => {
                                    let status = e.status().unwrap();

                                    log::error(&format!(
                                        "Can't delete file: {}",
                                        status.to_string().red()
                                    ));
                                }
                            },

                            Err(e) => {
                                log::error(&format!("Error on rm: {}", e.to_string().red()));
                            }
                        }
                    } else {
                        log::error(&format!("Can't find file {}", args.name.red()));
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
        "Remove the given file in the current folder".into()
    }
}
