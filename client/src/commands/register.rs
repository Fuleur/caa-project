use colored::Colorize;
use opaque_ke::{ClientRegistration, RegistrationRequest, RegistrationResponse, ClientRegistrationFinishParameters};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{log, DefaultCS, TSFSContext};

use super::Command;

pub struct RegisterCommand;

#[derive(Serialize, Deserialize, Debug)]
struct RegisterRequest {
    username: String,
    registration_request: RegistrationRequest<DefaultCS>,
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
            let mut client_rng = OsRng;
            let client_registration_start_result =
                ClientRegistration::<DefaultCS>::start(&mut client_rng, b"password").unwrap();

            let client = reqwest::blocking::Client::new();
            let res = client
                .post(format!(
                    "{}:{}/auth/register/start",
                    endpoint_url, ctx.endpoint_port
                ))
                .json(&RegisterRequest {
                    username: "test".into(),
                    registration_request: client_registration_start_result.message,
                })
                .send()
                .unwrap();

            let client_registration_finish_result = client_registration_start_result.state.finish(
                &mut client_rng,
                b"password",
                res.json::<RegistrationResponse<DefaultCS>>().unwrap(),
                ClientRegistrationFinishParameters::default(),
            ).unwrap();

            let _res = client
                .post(format!(
                    "{}:{}/auth/register/finish",
                    endpoint_url, ctx.endpoint_port
                ))
                .json(&client_registration_finish_result.message)
                .send()
                .unwrap();

            log::debug("Registration complete ! You can now login.");
        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Register to the endpoint".into()
    }
}
