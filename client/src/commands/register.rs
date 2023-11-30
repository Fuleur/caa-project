use colored::Colorize;

use crate::{TSFSContext, log};

use super::Command;

pub struct RegisterCommand;

impl Command for RegisterCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_some() {
            log::error(&format!("Already connected, must {} first", "logout".green()));
            return;
        }
        
        if let Some(endpoint_url) = &ctx.endpoint_url {

        } else {
            log::error(&format!("Missing {} in context", "endpoint_url".green()));
        }
    }

    fn description(&self) -> String {
        "Register to the endpoint".into()
    }
}
