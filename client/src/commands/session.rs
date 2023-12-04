use std::io::{self, Write};

use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use colored::Colorize;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{log, DefaultCS, TSFSContext};

use super::Command;

pub struct SessionCommand;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestResult {
    keypair: (Vec<u8>, Vec<u8>),
}

impl Command for SessionCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_none() {
            log::info("Not connected");
            return;
        }

        if let Some(endpoint_url) = &ctx.endpoint_url {
            let client = reqwest::blocking::Client::new();

            let res = client
                .get(format!(
                    "{}:{}/auth/session",
                    endpoint_url, ctx.endpoint_port
                ))
                .header("Authorization", ctx.session_token.as_ref().unwrap())
                .send();

            if res.is_err() {
                log::error(&format!("{}", res.err().unwrap()));
                return;
            }

            let res = match res.unwrap().error_for_status() {
                Ok(res) => res,
                Err(e) => {
                    log::error(&format!(
                        "Error on login: {}",
                        e.status().unwrap().to_string().red()
                    ));

                    return;
                }
            };

            log::info(&format!("{:?}", res.json::<Session>().unwrap()));
        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Test session".into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Session {
    token: String,
    user: String,
    expiration_date: u64,
}