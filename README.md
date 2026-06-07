# mitm

A Man-in-the-Middle (MITM) proxy implemented in Go.

## Overview

This project provides a simple MITM proxy to intercept, inspect, or modify network traffic.

## Project Structure

- `cmd/`: Command line entry point.
- `certs/`: Directory for SSL/TLS certificates used for HTTPS inspection.
- `interceptor/`: Core logic for intercepting and handling requests/responses.
- `handler.go`: HTTP handler implementation.

## Requirements

- Go (Golang)
