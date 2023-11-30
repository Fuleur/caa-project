use crate::TSFSContext;

pub mod exit;
pub mod help;
pub mod login;
pub mod logout;
pub mod ping;
pub mod register;
pub mod set;

pub trait Command {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext);
    fn description(&self) -> String;
}

pub fn parse(str: &str) -> Vec<String> {
    let str = str.replace('\n', "").replace('\r', "");
    let args = shell_words::split(&str).unwrap();

    args
}
