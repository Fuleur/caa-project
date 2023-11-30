use colored::Colorize;

use crate::{TSFSContext, log};

use super::Command;

pub struct LoginCommand;

impl Command for LoginCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_some() {
            log::info("Already connected");
            return;
        }

        if let Some(endpoint_url) = &ctx.endpoint_url {

        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Login to the endpoint".into()
    }
}
