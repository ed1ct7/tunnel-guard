mod app;
mod cli;
mod commands;
mod process_groups;
mod rules;
mod settings;
mod status;
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
