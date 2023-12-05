use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::{log, TSFSContext};

use super::Command;

pub struct SessionCommand;

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
                .header("Authorization", format!("Bearer {}", ctx.session_token.as_ref().unwrap()))
                .send();

            if res.is_err() {
                log::error(&format!("{}", res.err().unwrap()));
                return;
            }

            let res = match res.unwrap().error_for_status() {
                Ok(res) => res,
                Err(e) => {
                    log::error(&format!(
                        "Invalid session: {}",
                        e.status().unwrap().to_string().red()
                    ));

                    // Server cannot validate session, unset current session token
                    ctx.session_token = None;

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