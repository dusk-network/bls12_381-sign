# Change log

## 2021-10-20

A gRPC/Protobuf client running over Unix Domain Sockets was added to this repository and using closures and
setup/teardown functions it can switch between using the Cgo implementation in-process, or spawn the Rust
based `bls12_381-sign` microservice.

There were problems initially, with the UDS and a TCP version was first implemented, but turned out to be simply a minor
gotcha in the Go UDS dialing that requires the `unix://` URI protocol prefix while it wasn't needed for the
stdlib `net.Dial`, but is needed for `grpc.Dial`.

There is several new entries in the `Makefile`, most notably `benchmem` runs a full benchmark of the Cgo, gRPC/Protobuf
microservice, and even runs the Rust benchmarks. The output isn't prettified yet, but should be for proper benchmarking.
A VPS has been dedicated to this task and web interface triggers to run the tests on a given commit will be added in the
near future.
