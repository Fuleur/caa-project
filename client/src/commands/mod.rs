use std::time::SystemTime;

use crate::{log, models::KeyringWithKeysAndFiles, TSFSContext};

pub mod cd;
pub mod change_password;
pub mod exit;
pub mod help;
pub mod login;
pub mod logout;
pub mod ls;
pub mod mkdir;
pub mod ping;
pub mod register;
pub mod rm;
pub mod sessions;
pub mod set;
pub mod share;
pub mod upload_file;

pub trait Command {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext);
    fn description(&self) -> String;
}

pub fn parse(str: &str) -> Vec<String> {
    let str = str.trim();
    match shell_words::split(&str) {
        Ok(args) => args,

        Err(_) => vec![],
    }
}

pub fn update_keyring(ctx: &mut TSFSContext) {
    if ctx.session_token.is_none() {
        log::info("Not connected");
        return;
    }

    log::info("Updating keyring...");

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(ctx.accept_invalid_cert)
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "{}:{}/keyring",
            ctx.endpoint_url.as_ref().unwrap(),
            ctx.endpoint_port
        ))
        .header(
            "Authorization",
            format!("Bearer {}", ctx.session_token.as_ref().unwrap()),
        )
        .send();

    match res {
        Ok(res) => match res.error_for_status() {
            Ok(res) => {
                let keyring = res.json::<KeyringWithKeysAndFiles>().unwrap();
                let dec_keyring = KeyringWithKeysAndFiles::from_encrypted(
                    keyring,
                    ctx.private_key.as_ref().unwrap(),
                    true,
                );

                ctx.keyring_tree = Some(dec_keyring);
                ctx.last_keyring_update = SystemTime::now();
            }

            Err(e) => {
                log::error(&format!("Error while updating keyring: {}", e));
            }
        },
        Err(e) => {
            log::error(&format!("Error while updating keyring: {}", e));
        }
    }
}
