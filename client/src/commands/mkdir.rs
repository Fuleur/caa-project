use base64::prelude::*;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, ChaChaPoly1305, Nonce,
};
use clap::Parser;
use colored::Colorize;
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::der::Encode, sha2::Sha256, Oaep, RsaPublicKey};
use serde::Serialize;
use std::io::Read;

use crate::{crypto, log, models::FileWithoutDataWithKeyring, TSFSContext};

use super::Command;

#[derive(Serialize)]
pub struct CreateFolderRequest {
    /// The parent folder to put the file in.
    /// None = root
    parent_uid: Option<String>,
    /// Encrypted filename
    filename: String,
    /// Encrypted symmetric key with user pubkey
    encrypted_key: Vec<u8>,
}

/// List the content of the current folder
#[derive(Parser, Debug)]
pub struct MkdirArgs {
    name: String,
}

pub struct MkdirCommand;

impl Command for MkdirCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match MkdirArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(keyring_tree) = &ctx.keyring_tree {
                    // TODO: Request new Keyring Tree to the Server

                    log::info("Creating new folder...");

                    let mut current_folder = None;
                    if let Some(current_folder_id) = ctx.current_folder.last() {
                        current_folder = keyring_tree.get_file(current_folder_id);
                    };

                    let mut rng = OsRng;

                    // Create new asymmetric key for new folder
                    let key = ChaCha20Poly1305::generate_key(&mut rng);

                    // Encrypt folder name
                    let cipher = ChaCha20Poly1305::new(&key);
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let enc_name = cipher.encrypt(&nonce, args.name.as_bytes()).unwrap();
                    let enc_name = [nonce.to_vec(), enc_name].concat();
                    let enc_name_b64 = BASE64_STANDARD.encode(enc_name);

                    // Encrypt key with user public key or parent symmetric key
                    let enc_key;
                    if let Some(parent_folder) = current_folder {
                        let parent_key = parent_folder.key.as_slice();
                        enc_key = crypto::chacha_encrypt(key.as_slice(), parent_key).unwrap();
                    } else {
                        let pubkey = ctx.public_key.as_ref().unwrap();
                        enc_key = crypto::rsa_encrypt(&key, pubkey).unwrap();
                    }

                    let client = reqwest::blocking::Client::builder()
                        .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                        .build()
                        .unwrap();

                    let res = client
                        .post(format!(
                            "{}:{}/folder/create",
                            ctx.endpoint_url.as_ref().unwrap(),
                            ctx.endpoint_port
                        ))
                        .header(
                            "Authorization",
                            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                        )
                        .json(&CreateFolderRequest {
                            parent_uid: ctx.current_folder.last().cloned(),
                            filename: enc_name_b64,
                            encrypted_key: enc_key,
                        })
                        .send();

                    match res {
                        Ok(res) => match res.error_for_status() {
                            Ok(_) => {
                                log::info("Folder created !");
                            }

                            Err(e) => {
                                let status = e.status().unwrap();

                                log::error(&format!(
                                    "Can't create folder: {}",
                                    status.to_string().red()
                                ));
                            }
                        },

                        Err(e) => {
                            log::error(&format!("Error on mkdir: {}", e.to_string().red()));
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
