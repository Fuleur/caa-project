use colored::Colorize;

use crate::{TSFSContext, log};

use super::Command;

pub struct LogoutCommand;

impl Command for LogoutCommand {
    fn execute(&self, _args: &Vec<String>, ctx: &mut TSFSContext) {
        if ctx.session_token.is_none() {
            log::info("You are not connected");
        } else {
            ctx.session_token = None;
            log::info(&format!("Disconnected from {} !", ctx.endpoint_url.as_ref().unwrap().cyan()));
        }
    }

    fn description(&self) -> String {
        "Logout from the endpoint".into()
    }
}
