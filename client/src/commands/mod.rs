use crate::TSFSContext;

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
pub mod sessions;
pub mod set;
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
