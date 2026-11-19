mod app;
mod cli;
mod commands;
mod core_rules;
mod detect;
mod diagnose;
mod history;
mod http;
mod monitor;
mod process_groups;
mod progress;
mod rules;
mod settings;
mod status;
#[cfg(test)]
mod test_support;
mod tray;
#[cfg(windows)]
mod windows;

pub(crate) type Result<T> = std::result::Result<T, String>;

pub fn run() {
    if let Some(code) = app::worker_exit_code() {
        std::process::exit(code);
    }
    app::run();
}

pub fn run_cli() -> i32 {
    cli::run()
}
