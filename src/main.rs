mod cli;
mod config;
mod desktop;
mod git;
mod harness;
mod integrations;
mod inventory;
mod jobs;
mod manifest;
mod mcp;
mod notification;
#[allow(dead_code)]
mod output;
mod platform;
mod project;
mod resources;
mod rpc;
mod scheduler;
mod setup;
mod transport;

use clap::error::ErrorKind;

fn main() {
    if let Err(error) = cli::Cli::try_parse_process() {
        let exit = match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => output::StyrnExit::Success,
            _ => output::StyrnExit::Usage,
        };

        error.print().expect("writing CLI output must succeed");
        if exit != output::StyrnExit::Success {
            output::exit_process(exit);
        }
    }
}
