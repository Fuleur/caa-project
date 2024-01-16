use clap::Parser;
use colored::Colorize;
use serde::Serialize;

use crate::{crypto, log, TSFSContext};

use super::Command;

#[derive(Serialize)]
pub struct ShareFileRequest {
    /// File to share
    file_uid: String,
    /// Symmetric key of the file, encrypted with target_user public key
    encrypted_key: Vec<u8>,
    /// The user to share the file with
    target_user: String,
}

/// Share a file
#[derive(Parser, Debug)]
pub struct ShareArgs {
    filename: String,
    username: String,
}

pub struct ShareCommand;

impl Command for ShareCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match ShareArgs::try_parse_from(args) {
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

                    if let Some(file) = current_keyring.get_file_by_name(&args.filename) {
                        let client = reqwest::blocking::Client::builder()
                            .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                            .build()
                            .unwrap();

                        // First, request the public key of the user
                        let user_pubkey = match client
                            .get(format!(
                                "{}:{}/pubkey/{}",
                                ctx.endpoint_url.as_ref().unwrap(),
                                ctx.endpoint_port,
                                args.username
                            ))
                            .header(
                                "Authorization",
                                format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                            )
                            .send()
                        {
                            Ok(res) => match res.error_for_status() {
                                Ok(res) => res.json::<Vec<u8>>().unwrap(),

                                Err(e) => {
                                    log::error(&format!(
                                        "Error while requesting user pubkey {}",
                                        e
                                    ));
                                    return;
                                }
                            },

                            Err(e) => {
                                log::error(&format!("Error while requesting user pubkey {}", e));
                                return;
                            }
                        };

                        // Encrypt the file symmetric key with user pubkey
                        let enc_key = crypto::rsa_encrypt(&file.key, &user_pubkey).unwrap();

                        // Send the share request
                        let res = client
                            .post(format!(
                                "{}:{}/file/share",
                                ctx.endpoint_url.as_ref().unwrap(),
                                ctx.endpoint_port
                            ))
                            .header(
                                "Authorization",
                                format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                            )
                            .json(&ShareFileRequest {
                                file_uid: file.file.id,
                                encrypted_key: enc_key,
                                target_user: args.username.clone(),
                            })
                            .send();

                        match res {
                            Ok(res) => match res.error_for_status() {
                                Ok(_) => {
                                    log::info(&format!(
                                        "File shared with {} !",
                                        args.username.green()
                                    ));

                                    // update_keyring(ctx);
                                }

                                Err(e) => {
                                    let status = e.status().unwrap();

                                    log::error(&format!(
                                        "Can't share file: {}",
                                        status.to_string().red()
                                    ));
                                }
                            },

                            Err(e) => {
                                log::error(&format!("Error on share: {}", e.to_string().red()));
                            }
                        }
                    } else {
                        log::error(&format!("Can't find file {}", args.filename.red()));
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
        "Share the given file in the current folder to the given user".into()
    }
}
