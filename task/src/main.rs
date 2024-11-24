//! This file acts as the entry point of the task module, setting up the CLI interface and delegating tasks to the appropriate subcommands.
//! It uses subcommands to decide whether to build the eBPF program or run the user-space application.

#![allow(warnings)] 

mod build_ebpf; 
mod run; 

use std::process::exit; // Import the exit function to terminate the program
use clap::Parser; // Import the Parser trait from the clap crate for command-line argument parsing

/// The main options for the program, including a subcommand that can either
/// build eBPF or run eBPF.
#[derive(Debug, Parser)]
pub struct Options {
    /// The subcommand to execute. Can be either 'build' or 'run'.
    #[clap(subcommand)]
    command: Command,
}

/// Enum to represent the different subcommands that the program supports.
/// Each subcommand has its own options.
#[derive(Debug, Parser)]
enum Command {
    /// Build the eBPF program. Uses options from the build_ebpf module.
    BuildEbpf(build_ebpf::Options),

    /// Run the eBPF program. Uses options from the run module.
    Run(run::Options),
}

/// The entry point for the program. It parses command-line options and
/// invokes the appropriate subcommand (either 'BuildEbpf' or 'Run') based on
/// user input.
fn main() {
    // Parse the command-line arguments
    let opts = Options::parse();

    use Command::*; // Import enum variants to match against

    // Match on the subcommand chosen by the user and call the respective function
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts), // Build eBPF with provided options
        Run(opts) => run::run(opts), // Run eBPF with provided options
    };

    // If an error occurred, print the error and exit with a non-zero status code
    if let Err(e) = ret {
        eprintln!("{e:#}"); // Print the error in a pretty-printed format
        exit(1); // Exit the program with status code 1
    }
}
