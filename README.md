# Scale

Scale is a Tailscale alternative VPN solution developed in Go, designed for secure, scalable, and private network connectivity. This project implements both the server and client logic to provide seamless and efficient peer-to-peer networking.

## Overview

Scale aims to provide a lightweight, WireGuard-based VPN system that enables devices to connect securely over the internet as if they were on the same local network. The project includes:

- A custom control server that manages device authentication, IP address assignment, and configuration distribution.
- A client implementation that securely connects to the server, handles routing, and establishes encrypted peer connections.

## Features

- Complete server and client implementation in Go
- Device authentication and management
- IP address allocation from a managed pool
- Dynamic route management and peer configuration
- WireGuard-based encrypted tunnels for secure communication
- Designed for scalability and maintainability

## Repository Structure

- `server/`: Server-side code including authentication, IP management, and configuration serving
- `client/`: Client-side code handling device connection, routing, and communication with the server
- `routes.go` and `ipmanager.go`: Core networking utilities and IP management on both client and server
- PostgreSQL integration for device information storage and management

## Getting Started

### Prerequisites

- Go 1.20+
- PostgreSQL database for server device storage
- WireGuard kernel module or userspace tools installed on client devices

### Installation

Clone the repository and build the binaries:

```bash
git clone https://github.com/HeLiX-x/scale.git
cd scale
go build ./server
go build ./client

Configuration

Configure the server with your PostgreSQL connection details and network settings. Clients need to be registered with the server to receive configuration and IP addresses.
Running

Start the server:
./server

Start a client:
./client

Contribution

Contributions to improve the project are welcome. Please create issues and pull requests for bug fixes, features, or documentation enhancements.
License

This project is currently unlicensed. Feel free to contact the author for licensing inquiries.
Contact

For questions and support, reach out via the GitHub repository issues or contact the author.

Scale is an evolving project with the goal of providing a robust and secure alternative to Tailscale for private networking needs.

This version improves readability, proper formatting, and completes the "Start a client" section. It’s suitable as a professional project README.
