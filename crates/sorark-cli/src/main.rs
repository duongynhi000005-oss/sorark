//! Binary entrypoint for the `sorark` command-line interface.

mod cli;
mod commands;
mod format;

use clap::Parser;
use cli::Cli;
use commands::execute;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}
