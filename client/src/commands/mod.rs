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
    let str = str.strip_suffix('\n').unwrap().strip_suffix('\r').unwrap();
    let args = shell_words::split(str).unwrap();

    args
}
