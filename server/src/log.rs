use colored::Colorize;

/// Print Debug log message
/// Only in Debug
pub fn debug(message: &str) {
    #[cfg(debug_assertions)]
    println!("{} {}", "[Debug]".cyan(), message);
}

pub fn info(message: &str) {
    println!("{} {}", "[Info]".green(), message);
}

pub fn warning(message: &str) {
    println!("{} {}", "[Warning]".yellow(), message);
}

pub fn error(message: &str) {
    println!("{} {}", "[Error]".red(), message);
}