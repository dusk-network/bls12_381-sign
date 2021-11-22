# gRPC Client for BLS12-381 Sign

`bls.go` implements the [Bls12381Sign Interface](https://github.com/dusk-network/bls12_381-sign/go/bls.go) within a simple IPC-based gRPC client that interfaces with a running instance of our provided [gRPC server](https://github.com/dusk-network/bls12_381-sign/rust/grpc-server).

## Building

`Makefile` at the repo root takes care of everything, but essentially you'll need the following to build the code:
 - The compiled protobuf definitions (with the auto-generated client implementation)
 - The [service](https://github.com/dusk-network/bls12_381-sign/rust/grpc-server) binaries for your platform, so `go:embed` directives can find them.

## Usage

This module exports all required methods to satisfy the [Bls12381Sign Interface](https://github.com/dusk-network/bls12_381-sign/go/bls.go), as well as a `Connect()` and `Disconnect()` method which should be used to encapsulate actual calls to the library. Please check `bls_test.go` for a few examples.