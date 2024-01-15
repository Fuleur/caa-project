use std::io::{self, Write};

use base64::{engine::general_purpose, Engine};
use chacha20poly1305::Key;
use colored::Colorize;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, Identifiers, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{crypto, log, DefaultCS, TSFSContext};

use super::Command;

pub struct RegisterCommand;

#[derive(Serialize, Deserialize, Debug)]
struct RegisterRequest {
    username: String,
    registration_request: RegistrationRequest<DefaultCS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    username: String,
    registration_upload: RegistrationUpload<DefaultCS>,
    // (pub_key, priv_key)
    user_keypair: (Vec<u8>, Vec<u8>),
}

impl Command for RegisterCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_some() {
            log::error(&format!(
                "Already connected, must {} first",
                "logout".green()
            ));
            return;
        }

        if let Some(endpoint_url) = &ctx.endpoint_url {
            // Username input
            print!("Username: ");
            io::stdout().flush().unwrap();

            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();
            username = username.trim().to_string();

            // Password input
            let password = rpassword::prompt_password("Password: ").unwrap();

            // Create ClientRegistration
            let mut client_rng = OsRng;
            let client_registration_start_result =
                ClientRegistration::<DefaultCS>::start(&mut client_rng, password.as_bytes())
                    .unwrap();

            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                .build()
                .unwrap();

            // Send RegistrationRequest to the Server
            let res = client
                .post(format!(
                    "{}:{}/auth/register/start",
                    endpoint_url, ctx.endpoint_port
                ))
                .json(&RegisterRequest {
                    username: username.clone(),
                    registration_request: client_registration_start_result.message,
                })
                .send();

            if res.is_err() {
                log::error(&format!("{}", res.err().unwrap()));
                return;
            }

            let res = res.unwrap();

            match res.error_for_status() {
                Ok(res) => {
                    // Create ClientRegistrationFinishResult
                    let client_registration_finish_result = client_registration_start_result
                        .state
                        .finish(
                            &mut client_rng,
                            password.as_bytes(),
                            // Get RegistrationResponse from Server
                            res.json::<RegistrationResponse<DefaultCS>>().unwrap(),
                            ClientRegistrationFinishParameters::new(
                                Identifiers {
                                    client: Some(username.as_bytes()),
                                    server: Some(b"TSFSServer"),
                                },
                                None,
                            ),
                        )
                        .unwrap();

                    // Get the Export Key from ClientRegistration
                    // The Export Key is the password derived key derived by the KSF (in our case Argon2) during the OPAQUE protocol
                    // This key will be used as Master Key
                    // See https://docs.rs/opaque-ke/latest/opaque_ke/#export-key for more informations
                    let export_key = client_registration_finish_result.export_key;
                    log::debug(&format!(
                        "Export Key: {}",
                        general_purpose::STANDARD_NO_PAD.encode(export_key)
                    ));

                    // Generate Keypair for User Keychain
                    log::info("Generating RSA Keypair...");
                    let mut rng = OsRng;
                    let priv_key =
                        RsaPrivateKey::new(&mut rng, 3072).expect("failed to generate a key");
                    let pub_key = RsaPublicKey::from(&priv_key);

                    log::info("Encrypting private key...");

                    // Need to shrink the 64 bytes Export Key to 32 bytes
                    let key = Key::from_slice(&export_key[..32]);
                    let encrypted_private_key =
                        crypto::chacha_encrypt(priv_key.to_pkcs1_der().unwrap().as_bytes(), key)
                            .unwrap();

                    log::info("Sending RegistrationFinish to Server...");

                    // Send RegistrationUpload to the Server
                    match client
                        .post(format!(
                            "{}:{}/auth/register/finish",
                            endpoint_url, ctx.endpoint_port
                        ))
                        .json(&RegisterFinishRequest {
                            username,
                            registration_upload: client_registration_finish_result.message,
                            user_keypair: (
                                pub_key.to_pkcs1_der().unwrap().to_vec(),
                                encrypted_private_key,
                            ),
                        })
                        .send()
                    {
                        Ok(res) => {
                            match res.error_for_status() {
                                Ok(_) => {
                                    log::info("Registration complete ! You can now login.");
                                }

                                Err(e) => {
                                    let status = e.status().unwrap();

                                    if status == StatusCode::CONFLICT {
                                        log::error("An account is already registered with this username :/");
                                    } else {
                                        log::error(&format!(
                                            "Error on register: {}",
                                            e.to_string().red()
                                        ));
                                    }
                                }
                            }
                        }

                        Err(e) => {
                            log::error(&format!("Error on register: {}", e.to_string().red()));
                        }
                    };
                }

                Err(e) => {
                    let status = e.status().unwrap();

                    if status == StatusCode::CONFLICT {
                        log::error("An account is already registered with this username :/");
                    } else {
                        log::error(&format!("Error on register: {}", e.to_string().red()));
                    }
                }
            }
        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Register to the endpoint".into()
    }
}
