use std::time::{Duration, UNIX_EPOCH};

use chrono::prelude::*;
use clap::Parser;
use colored::Colorize;
use serde::Deserialize;

use crate::{log, TSFSContext};

use super::Command;

pub struct SessionsCommand;

#[derive(Deserialize, Debug)]
pub struct SessionInfo {
    token_short: String,
    expiration_date: i64,
    current: bool,
}

/// Sessions related command
#[derive(Parser, Debug)]
pub struct SessionsArgs {
    /// Clear all active sessions (expect current one)
    #[arg(short, long)]
    clear: bool,
}

impl Command for SessionsCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match SessionsArgs::try_parse_from(args) {
            Ok(args) => {
                if ctx.session_token.is_none() {
                    log::info("Not connected");
                    return;
                }

                if ctx.endpoint_url.is_some() {
                    if args.clear {
                        clear_sessions(ctx);
                    } else {
                        get_sessions(ctx);
                    }
                } else {
                    log::error(&format!("Missing {} in context", "endpoint_url".green()));
                }
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "Test session".into()
    }
}

fn clear_sessions(ctx: &mut TSFSContext) {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(ctx.accept_invalid_cert)
        .build()
        .unwrap();

    let res = client
        .post(format!(
            "{}:{}/auth/revoke_all",
            ctx.endpoint_url.as_ref().unwrap(),
            ctx.endpoint_port
        ))
        .header(
            "Authorization",
            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
        )
        .send();

    if res.is_err() {
        log::error(&format!("{}", res.err().unwrap()));
        return;
    }

    match res.unwrap().error_for_status() {
        Ok(_) => log::info("Sessions cleared !"),
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
}

fn get_sessions(ctx: &mut TSFSContext) {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(ctx.accept_invalid_cert)
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "{}:{}/auth/sessions",
            ctx.endpoint_url.as_ref().unwrap(),
            ctx.endpoint_port
        ))
        .header(
            "Authorization",
            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
        )
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

    let sessions = res.json::<Vec<SessionInfo>>().unwrap();

    log::info(&format!("You have {} active sessions: ", sessions.len()));
    for session in sessions {
        println!(
            "  {} : Valid until {}",
            if session.current {
                (session.token_short + " [current]").green()
            } else {
                session.token_short.cyan()
            },
            DateTime::<Local>::from(
                UNIX_EPOCH + Duration::from_millis(session.expiration_date as u64)
            )
            .to_string()
            .green()
        );
    }
    log::info(&format!(
        "You can revoke all sessions expect current one with {} command",
        "sessions --clear".green()
    ));
}
