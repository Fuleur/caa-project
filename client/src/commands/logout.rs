use colored::Colorize;

use crate::{log, TSFSContext};

use super::Command;

pub struct LogoutCommand;

impl Command for LogoutCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_none() {
            log::info("You are not connected");
        } else {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(ctx.accept_invalid_cert)
                .build()
                .unwrap();

            // Revoke current Session Token
            client
                .post(format!(
                    "{}:{}/auth/revoke",
                    ctx.endpoint_url.as_ref().unwrap(),
                    ctx.endpoint_port
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
                )
                .send()
                .unwrap();

            ctx.session_token = None;
            log::info(&format!(
                "Disconnected from {} !",
                ctx.endpoint_url.as_ref().unwrap().cyan()
            ));
        }
    }

    fn description(&self) -> String {
        "Logout from the endpoint".into()
    }
}
