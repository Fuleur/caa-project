use colored::Colorize;

/// Print Debug log message, not printed in release build
#[allow(dead_code)]
pub fn debug(message: &str) {
    #[cfg(debug_assertions)]
    println!("{} {}", "[Debug]".cyan(), message);
}

#[allow(dead_code)]
pub fn info(message: &str) {
    println!("{} {}", "[Info]".green(), message);
}

#[allow(dead_code)]
pub fn warning(message: &str) {
    println!("{} {}", "[Warning]".yellow(), message);
}

#[allow(dead_code)]
pub fn error(message: &str) {
    println!("{} {}", "[Error]".red(), message);
}