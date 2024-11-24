# Dynamic TCP Packet Dropper

## Overview
The **Dynamic TCP Packet Dropper** is a Rust-based project that uses **eBPF (Extended Berkeley Packet Filter)** to monitor and block specific TCP packets on designated ports in a network. The project demonstrates the power of eBPF for network traffic manipulation in real-time, leveraging Rust for the user-space components.

This project includes a modular approach to interacting with eBPF programs that drop TCP packets on a given port (default is `4040`). The interaction between kernel space and user space is handled with the **AYA** library, a pure Rust eBPF library.

The project is packaged and Dockerized for ease of setup and deployment.

## Features
1.Block specific TCP packets based on the target port (default: 4040).
2.User-space program in Rust that manages eBPF programs.
3.Modular architecture separating eBPF program loading, packet filtering, and logging.
4.Support for attaching to network interfaces using **XDP (eXpress Data Path)**.
5. Configurable to block traffic on any given IP and port.
6. Logging and error-handling mechanisms in the user space.
 

## Architecture
- **eBPF Kernel Program**: The core program intercepts and inspects network packets, filtering out those targeting specific ports (default `4040`).
- **Rust User-space Program**: Manages the interaction with eBPF, including loading the program, attaching it to network interfaces, and logging.
- **Docker Container**: Dockerized environment for consistent and reproducible builds and deployments.

## Requirements

### Software Dependencies
1. **Rust Toolchain**: Ensure you have both stable and nightly versions of Rust installed.
   - Install Rust (stable and nightly) using [rustup](https://rustup.rs/).
   - Install a rust nightly toolchain: `rustup install nightly`


   - Install **BPF-Linker** via Cargo:
     ```bash
     cargo install bpf-linker
     ```

2. **Linux Kernel**: The project requires a Linux distribution with kernel version 5.x or higher to support eBPF.

3. **LLVM**: Required for compiling eBPF programs.

4. **Docker**: To build and run the project within a containerized environment.

### Packages Installed in Docker
- Ubuntu 22.04-based Docker image.
- Essential development packages like `build-essential`, `libssl-dev`, `clang`, `llvm`, `git`, `nginx`, etc.
- Rust and necessary toolchains (stable and nightly), along with **BPF-Linker** for eBPF compilation.

## Main Components
1. The project employs data structures that enable interaction between kernel space and userspace.
2. It invloves logic to extract relevant packet headers, specifically Ethernet, IP, and TCP headers to inspect network traffic.
3. The program identifies packets intended for port 4040 and drops them accordingly.
## How it works

1. **Initialization**: The eBPF program is attached to a network interface.
2. **Packet Interception**: Incoming network packets are intercepted and analyzed by the eBPF program.
3. **Header Inspection**: Ethernet, IP, and TCP headers are extracted to determine the destination port.
4. **Packet Dropping**: If a packet is targeting port 4040, it is dropped. Otherwise, it is allowed to pass through the network.


## Installation and Setup

### Dockerized Setup

### 1. Pull the Docker Image
Start by pulling the Docker image:
```bash
sudo docker pull rmg0070/tcppacketdropper:latest

```
### 2. RUNNING THE PULLED IMAGE
``` bash
sudo docker run --privileged -it -p 80:80 --name ebpf rmg0070/tcppacketdropper:latest /bin/bash
```
This starts an interactive shell inside the Docker container, allowing you to run the project.

### 3. IP BLOCKING AND PORT BLOCING 
ENTER IP THAT HAS TO BE BLOCKED 
```BASH
RUST_LOG=info cargo task run --ip-address=192.168.1.100 --port=80
```

## Building the Project
## Build eBPF Program
To build the eBPF kernel program, run the following command inside the container:
```bash
cargo task build-ebpf
```

## Build Userspace Program

```bash
cargo build
```
This compiles the user-space Rust code, which interacts with the eBPF program to load and manage packet filtering.


## Running the Application
```bash
cargo task run
```

This will start the process that listens for incoming TCP packets and drops any packet targeting the specified port (4040 by default).

## Blocking Specific IPs and Ports
ENTER IP THAT HAS TO BE BLOCKED 
```BASH
RUST_LOG=info cargo task run --ip-address=192.168.1.100 --port=80
```

## Testing the Application   
```bash
cargo test
```
This will run the unit or integration tests defined in this project to verify the functionality.
