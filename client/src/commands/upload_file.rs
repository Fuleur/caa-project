use base64::prelude::*;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use clap::Parser;
use colored::Colorize;
use rsa::{pkcs1::DecodeRsaPublicKey, rand_core::OsRng, sha2::Sha256, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::{log, models::KeyringWithKeys, TSFSContext};

use super::Command;

pub struct UploadFileCommand;

/// Upload a local file to the remote server
#[derive(Parser, Debug)]
pub struct UploadFileArgs {
    local_path: String,
    remote_path: String,
}

#[derive(Serialize)]
pub struct UploadFileRequest {
    path: String,
    filename: String,
    file: Vec<u8>,
    encrypted_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct UploadFileResponse {
    keyring: KeyringWithKeys,
}

impl Command for UploadFileCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match UploadFileArgs::try_parse_from(args) {
            Ok(args) => {
                if ctx.session_token.is_none() {
                    log::info("Not connected");
                    return;
                }

                let endpoint_url = ctx.endpoint_url.as_ref().unwrap();

                let file_path = Path::new(&args.local_path);
                log::debug(file_path.to_str().unwrap());

                // Get local file
                if let Ok(file_content) = fs::read(file_path) {
                    // Encrypt file
                    let mut rng = OsRng;

                    let file_key = ChaCha20Poly1305::generate_key(&mut OsRng);
                    let cipher = ChaCha20Poly1305::new(&file_key);
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

                    let encrypted_file = cipher.encrypt(&nonce, file_content.as_ref()).unwrap();
                    let file_content_ciphertext = [nonce.to_vec(), encrypted_file].concat();

                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

                    let encrypted_filename = cipher
                        .encrypt(
                            &nonce,
                            file_path.file_name().unwrap().to_str().unwrap().as_bytes(),
                        )
                        .unwrap();
                    let filename_ciphertext = [nonce.to_vec(), encrypted_filename].concat();
                    let filename_base64 = BASE64_STANDARD.encode(filename_ciphertext);

                    // Encrypt file key with user public key
                    let rsa_public_key =
                        RsaPublicKey::from_pkcs1_der(ctx.public_key.as_ref().unwrap()).unwrap();
                    let padding = Oaep::new::<Sha256>();

                    let encrypted_key = rsa_public_key
                        .encrypt(&mut rng, padding, &file_key)
                        .unwrap();

                    let client = reqwest::blocking::Client::builder()
                        .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                        .build()
                        .unwrap();

                    match client
                        .post(format!(
                            "{}:{}/file/upload",
                            endpoint_url, ctx.endpoint_port
                        ))
                        .header(
                            "Authorization",
                            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                        )
                        .json(&UploadFileRequest {
                            path: args.local_path,
                            filename: filename_base64,
                            file: file_content_ciphertext,
                            encrypted_key,
                        })
                        .send()
                    {
                        Ok(res) => match res.error_for_status() {
                            Ok(res) => {
                                log::info("File upload success !");

                                let upload_result = res.json::<UploadFileResponse>().unwrap();
                                ctx.keyring = Some(upload_result.keyring);
                            }

                            Err(e) => {
                                log::error(&format!(
                                    "Error on file upload change: {}",
                                    e.to_string().red()
                                ));
                            }
                        },

                        Err(e) => {
                            log::error(&format!("Error on file upload: {}", e.to_string().red()));
                        }
                    };
                } else {
                    log::error("Can't read local file");
                }
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "Upload a local file to the remote server".into()
    }
}
