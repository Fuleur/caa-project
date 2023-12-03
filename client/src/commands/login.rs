use std::io::{self, Write};

use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{log, DefaultCS, TSFSContext};

use super::Command;

pub struct LoginCommand;

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    username: String,
    credential_request: CredentialRequest<DefaultCS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestFinish {
    username: String,
    credential_finalization: CredentialFinalization<DefaultCS>,
}

impl Command for LoginCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_some() {
            log::info("Already connected");
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

            // Create ClientLoginStart
            let mut client_rng = OsRng;
            let client_login_start_result =
                ClientLogin::<DefaultCS>::start(&mut client_rng, password.as_bytes()).unwrap();

            let client = reqwest::blocking::Client::new();

            // Send CredentialRequest to the Server
            let res = client
                .post(format!(
                    "{}:{}/auth/login/start",
                    endpoint_url, ctx.endpoint_port
                ))
                .json(&LoginRequest {
                    username: username.clone(),
                    credential_request: client_login_start_result.message,
                })
                .send();

            if res.is_err() {
                log::error(&format!("{}", res.err().unwrap()));
                return;
            }

            let res = res.unwrap();

            match res.error_for_status() {
                Ok(res) => {
                    // Create ClientLoginFinishResult
                    match client_login_start_result.state.finish(
                        password.as_bytes(),
                        // Get CredentialResponse from Server
                        res.json::<CredentialResponse<DefaultCS>>().unwrap(),
                        ClientLoginFinishParameters::new(
                            None,
                            Identifiers {
                                client: Some(username.as_bytes()),
                                server: Some(b"TSFSServer"),
                            },
                            None,
                        ),
                    ) {
                        Ok(client_login_finish_result) => {
                            // Send CredentialFinalization to the Server
                            let _res = client
                                .post(format!(
                                    "{}:{}/auth/login/finish",
                                    endpoint_url, ctx.endpoint_port
                                ))
                                .json(&LoginRequestFinish {
                                    username: username.clone(),
                                    credential_finalization: client_login_finish_result.message,
                                })
                                .send()
                                .unwrap();

                            // Here is our Session Key that will be used as Session Token
                            let b64_token = general_purpose::STANDARD_NO_PAD
                                .encode(client_login_finish_result.session_key);

                            ctx.username = Some(username.clone());
                            ctx.session_token = Some(b64_token.clone());
                            log::info(&format!(
                                "Login {} ! Welcome back {} !",
                                "OK".bright_green(),
                                username.bright_green()
                            ));
                            log::debug(&format!("Session Token: {}", b64_token));
                        }

                        Err(e) => {
                            log::error(&format!("{}", e));
                        }
                    }
                }

                Err(e) => {
                    log::error(&format!(
                        "Error on login: {}",
                        e.status().unwrap().to_string().red()
                    ));
                }
            }
        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Login to the endpoint".into()
    }
}
