use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use clap::Parser;
use colored::Colorize;
use serde::Serialize;

use crate::{crypto, log, TSFSContext};

use super::{download_file, update_keyring, Command};

#[derive(Serialize)]
pub struct RevokeShareFileRequest {
    /// File to revoke
    file_uid: String,
    /// A file can have multiple parents depending of sharing status
    /// We need to know the parent the file must remain in
    /// If user indicate a different parent on which he have also access
    /// This will move the file with this current implementation
    parent_uid: Option<String>,
    /// New Symmetric key of the file, encrypted with parent
    encrypted_key: Vec<u8>,
    /// New encrypted filename
    filename: String,
    /// New encrypted file content
    file: Option<Vec<u8>>,
}

/// Unshare a file
#[derive(Parser, Debug)]
pub struct UnshareArgs {
    filename: String,
}

pub struct UnshareCommand;

impl Command for UnshareCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match UnshareArgs::try_parse_from(args) {
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
                        if file.file.is_folder() {
                            log::warning("Unshare for folders not implemented yet :(");
                            return;
                        }

                        // Get file
                        if let Some(file) = download_file(ctx, file) {

                            // Encrypt file
                            let mut rng = OsRng;

                            let file_key = ChaCha20Poly1305::generate_key(&mut OsRng);
                            let cipher = ChaCha20Poly1305::new(&file_key);

                            let file_content_ciphertext = if let Some(data) = file.data {
                                let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

                                let encrypted_file = cipher
                                    .encrypt(&nonce, data.as_slice())
                                    .unwrap();

                                Some([nonce.to_vec(), encrypted_file].concat())
                            } else {
                                None
                            };

                            let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

                            let encrypted_filename =
                                cipher.encrypt(&nonce, file.name.as_bytes()).unwrap();
                            let filename_ciphertext = [nonce.to_vec(), encrypted_filename].concat();
                            let filename_base64 = BASE64_STANDARD.encode(filename_ciphertext);

                            let encrypted_key;
                            if let Some(current_folder) = ctx.current_folder.last() {
                                let current_folder = ctx
                                    .keyring_tree
                                    .as_ref()
                                    .unwrap()
                                    .get_file(&current_folder)
                                    .unwrap();

                                let key = current_folder.key;
                                encrypted_key = crypto::chacha_encrypt(&file_key, &key).unwrap();
                            } else {
                                // Encrypt file key with user public key
                                encrypted_key = crypto::rsa_encrypt(
                                    &file_key,
                                    ctx.public_key.as_ref().unwrap(),
                                )
                                .unwrap();
                            }

                            let client = reqwest::blocking::Client::builder()
                                .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                                .build()
                                .unwrap();

                            match client
                                .post(format!(
                                    "{}:{}/file/unshare",
                                    ctx.endpoint_url.as_ref().unwrap(),
                                    ctx.endpoint_port
                                ))
                                .header(
                                    "Authorization",
                                    format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                                )
                                .json(&RevokeShareFileRequest {
                                    file_uid: file.id,
                                    parent_uid: ctx.current_folder.last().cloned(),
                                    filename: filename_base64,
                                    file: file_content_ciphertext,
                                    encrypted_key,
                                })
                                .send()
                            {
                                Ok(res) => match res.error_for_status() {
                                    Ok(_res) => {
                                        log::info("File unshare success !");

                                        update_keyring(ctx);
                                    }

                                    Err(e) => {
                                        log::error(&format!(
                                            "Error on file unshare: {}",
                                            e.to_string().red()
                                        ));
                                    }
                                },

                                Err(e) => {
                                    log::error(&format!(
                                        "Error on file unshare: {}",
                                        e.to_string().red()
                                    ));
                                }
                            };
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
