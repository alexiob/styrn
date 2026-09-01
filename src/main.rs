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

fn main() {
    if let Err(failure) = cli::Cli::try_parse_process() {
        let exit = if failure.is_display() {
            output::StyrnExit::Success
        } else {
            output::StyrnExit::Usage
        };

        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        cli::render_parse_failure(&failure, &mut stdout.lock(), &mut stderr.lock())
            .expect("writing CLI output must succeed");
        if exit != output::StyrnExit::Success {
            output::exit_process(exit);
        }
    }
}
