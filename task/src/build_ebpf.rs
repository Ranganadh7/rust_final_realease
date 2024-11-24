#![allow(warnings)] 

use std::{path::PathBuf, process::Command}; // Import necessary modules from the standard library
use clap::Parser; // Import the Parser trait from the clap crate for command-line argument parsing

/// Enum representing the two possible architectures for the BPF target: BPF little-endian (BpfEl) and BPF big-endian (BpfEb).
#[derive(Debug, Copy, Clone)]
pub enum Architecture {
  
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    /// Parse a string into the corresponding Architecture enum variant.
    ///
    /// # Arguments * `s` - A string slice representing the architecture, e.g., "bpfel-unknown-none" or "bpfeb-unknown-none".
    /// # Returns
    /// * Ok(Architecture::BpfEl) for "bpfel-unknown-none".
    /// * Ok(Architecture::BpfEb) for "bpfeb-unknown-none".
    /// * Err with an error message if the input string is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()), // Return an error if the input is invalid
        })
    }
}

impl std::fmt::Display for Architecture {
    /// Display the Architecture enum as a string for output.
    /// # Arguments * `f` - A formatter to write the string representation of the Architecture.
    /// # Returns
    /// A string representing the architecture, e.g., "bpfel-unknown-none" or "bpfeb-unknown-none".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

/// Options for building the eBPF program, including the target architecture and release flag.
#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target architecture.
    /// Defaults to "bpfel-unknown-none" (little-endian).
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,

    /// Flag to indicate whether to build the release target.
    #[clap(long)]
    pub release: bool,
}

/// Function to build the eBPF program using Cargo with the specified options.
/// # Arguments  * `opts` - The command-line options, including target architecture and release flag.
/// # Returns
/// * Ok(()) if the build is successful.
/// * Err(anyhow::Error) if the build fails.
pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("ebpf"); // Path to the eBPF source directory
    let target = format!("--target={}", opts.target); // Format the target architecture string
    let mut args = vec![
        "build", // The command to build the eBPF program
        target.as_str(),
        "-Z", // Flag to specify the standard library for core
        "build-std=core",
    ];

    // If the release flag is set, add the --release argument to build in release mode
    if opts.release {
        args.push("--release");
    }

    // Use Command::new to spawn a child process that runs the cargo build command
    let status = Command::new("cargo")
        .current_dir(&dir) // Set the current working directory for the command
        .env_remove("RUSTUP_TOOLCHAIN") // Remove the RUSTUP_TOOLCHAIN environment variable to honor the rust-toolchain.toml file
        .args(&args) // Pass the arguments to the command
        .status() // Execute the command and capture the status
        .expect("failed to build bpf program"); // Panic if the command fails

   
    assert!(status.success());
    Ok(())
}
