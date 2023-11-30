use colored::Colorize;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse,
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
            let mut client_rng = OsRng;
            let client_login_start_result =
                ClientLogin::<DefaultCS>::start(&mut client_rng, b"password").unwrap();

            let client = reqwest::blocking::Client::new();
            let res = client
                .post(format!(
                    "{}:{}/auth/login/start",
                    endpoint_url, ctx.endpoint_port
                ))
                .json(&LoginRequest {
                    username: "test".into(),
                    credential_request: client_login_start_result.message,
                })
                .send()
                .unwrap();

            match res.error_for_status() {
                Ok(res) => {
                    match client_login_start_result.state.finish(
                        b"password",
                        res.json::<CredentialResponse<DefaultCS>>().unwrap(),
                        ClientLoginFinishParameters::default(),
                    ) {
                        Ok(client_login_finish_result) => {
                            let _res = client
                                .post(format!(
                                    "{}:{}/auth/login/finish",
                                    endpoint_url, ctx.endpoint_port
                                ))
                                .json(&LoginRequestFinish {
                                    username: "test".into(),
                                    credential_finalization: client_login_finish_result.message,
                                })
                                .send()
                                .unwrap();

                            log::debug(&format!(
                                "Login complete ! Token: {:?}",
                                client_login_finish_result.session_key
                            ));
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
