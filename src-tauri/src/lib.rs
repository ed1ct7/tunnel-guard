mod backend;
mod cli;
mod process_groups;

pub fn run() {
    if let Some(code) = backend::worker_exit_code() {
        std::process::exit(code);
    }
    backend::run();
}

pub fn run_cli() -> i32 {
    cli::run()
}
