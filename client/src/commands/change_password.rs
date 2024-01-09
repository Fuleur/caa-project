use base64::{engine::general_purpose, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key,
};
use colored::Colorize;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, Identifiers, RegistrationResponse,
    RegistrationUpload,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{log, DefaultCS, TSFSContext};

use super::Command;

pub struct ChangePasswordCommand;

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordChangeFinishRequest {
    registration_upload: RegistrationUpload<DefaultCS>,
    user_new_private_key: Vec<u8>,
}

impl Command for ChangePasswordCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_none() {
            log::error("Not connected, must login first");
            return;
        }

        if let Some(endpoint_url) = &ctx.endpoint_url {
            // Password input
            let password = rpassword::prompt_password("New Password: ").unwrap();

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
                    "{}:{}/auth/change_password/start",
                    endpoint_url, ctx.endpoint_port
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                )
                .json(&client_registration_start_result.message)
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
                                    client: Some(ctx.username.as_ref().unwrap().as_bytes()),
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

                    log::info("Encrypting private key...");
                    let mut rng = OsRng;

                    // Need to shrink the 64 bytes Export Key to 32 bytes
                    let key = Key::from_slice(&export_key[..32]);
                    let cipher = ChaCha20Poly1305::new(&key);
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

                    let encrypted_private_key = cipher
                        .encrypt(&nonce, ctx.private_key.as_ref().unwrap().as_ref())
                        .unwrap();
                    // Concat the nonce with the ciphertext
                    let private_key_cipher = [nonce.to_vec(), encrypted_private_key].concat();

                    log::info("Sending RegistrationFinish to Server...");

                    // Send RegistrationUpload to the Server
                    match client
                        .post(format!(
                            "{}:{}/auth/change_password/finish",
                            endpoint_url, ctx.endpoint_port
                        ))
                        .header(
                            "Authorization",
                            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                        )
                        .json(&PasswordChangeFinishRequest {
                            registration_upload: client_registration_finish_result.message,
                            user_new_private_key: private_key_cipher,
                        })
                        .send()
                    {
                        Ok(res) => match res.error_for_status() {
                            Ok(_) => {
                                log::info("Password change complete !");
                            }

                            Err(e) => {
                                log::error(&format!(
                                    "Error on password change: {}",
                                    e.to_string().red()
                                ));
                            }
                        },

                        Err(e) => {
                            log::error(&format!("Error on register: {}", e.to_string().red()));
                        }
                    };
                }

                Err(e) => {
                    log::error(&format!(
                        "Error on password change: {}",
                        e.to_string().red()
                    ));
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
