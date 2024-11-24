use std::process::Command; // Import Command from the standard library for running external commands
use std::net::Ipv4Addr; // Import Ipv4Addr for handling IPv4 addresses
use anyhow::{Context, Result, bail}; // Import error handling from the anyhow crate
use clap::Parser; // Import Parser trait from the clap crate for command-line argument parsing

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions}; // Import build_ebpf and related types from the build_ebpf module

/// Command-line options for building and running the project.
#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target architecture (default: "bpfel-unknown-none")
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,

    /// Flag to indicate whether to build the release target
    #[clap(long)]
    pub release: bool,

    /// Command used to wrap the application (default: "sudo -E")
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,

    /// Arguments to pass to the application when running it
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,

    /// Optional IP address to be blocked
    #[clap(long)]
    pub ip_address: Option<Ipv4Addr>,

    /// Optional port number to be blocked
    #[clap(long)]
    pub port: Option<u16>,
}

/// Build the userspace application using Cargo.
/// # Arguments * `opts` - Options containing the command-line flags such as release flag.

/// # Returns

/// * Ok(()) if the build is successful.
/// * Err(anyhow::Error) if the build fails with a descriptive error.
fn build(opts: &Options) -> Result<()> {
    let mut args = vec!["build"];
    
    // Add the --release flag if requested
    if opts.release {
        args.push("--release");
    }

    // Run the build command using Cargo
    let status = Command::new("cargo")
        .args(&args) // Pass the build arguments
        .status() // Execute the command and get the status
        .context("Failed to build userspace")?; // Add context to the error if it fails

    assert!(status.success()); // Ensure the build was successful
    Ok(())
}

/// Build and run the project, including building the eBPF program and userspace application.

/// # Arguments * `opts` - The command-line options for building and running the project.
///
/// # Returns

/// * Ok(()) if the build and run are successful.
/// * Err(anyhow::Error) if either the build or run fails with a descriptive error.
pub fn run(mut opts: Options) -> Result<()> {
    // Build the eBPF program using the provided options
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;

    // Build the userspace application
    build(&opts).context("Error while building userspace application")?;

    // Determine the profile (release or debug) for the build
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/xdp-drop");

    // Add IP address to run arguments if provided
    if let Some(ip) = opts.ip_address {
        opts.run_args.push(format!("--ip-address={}", ip));
    }
    // Add port to run arguments if provided
    if let Some(port) = opts.port {
        opts.run_args.push(format!("--port={}", port));
    }

    // Convert run_args from Vec<String> to Vec<&str> for passing to the command
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // Build the command arguments by splitting the runner string and appending the binary path and run arguments
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // Run the command using the constructed arguments
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1)) // Skip the first argument since it's the runner command
        .status() // Execute the command and get the status
        .context("Failed to run the command")?; // Add context to the error if it fails

    // If the command did not succeed, return an error with the command string
    if !status.success() {
        bail!("Failed to run `{}`", args.join(" "));
    }

    Ok(())
}
