# gRPC Server for BLS12-381 Sign

Implementation of a simple IPC-based server to provide a synchronous gRPC interface to the [BLS12-381 library](/rust/bls12_381-sign) to external parties.

## API definition
We use protobuf to strictly define the API. The schema is available [here](/schema/bls12381sig.proto).

## Building

`Makefile` at the repo root takes care of everything. Regardless, a simple `cargo build --release` should do the job if built independently. Built service binaries can be found at `./target/release`

## Usage

We provide a bloat-free [example](/go/grpc/bls) of a client written in Go which fully describes all API methods that can be used for reference.