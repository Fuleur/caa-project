pub mod exit;
pub mod help;
pub mod ping;

pub trait Command {
    fn execute(&self, args: &Vec<String>);
    fn description(&self) -> String;
}

pub fn parse(str: &str) -> Vec<String> {
    let str = str.strip_suffix('\n').unwrap();
    let args: Vec<String> = str.split(' ').map(|s| s.to_string()).collect();

    args
}
