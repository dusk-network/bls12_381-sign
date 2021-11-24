# gRPC Client for BLS12-381 Sign

`bls.go` provides an abstraction to interface with our [BLS12-381 Sign library](/rust/bls12_381-sign) via a simple IPC-based gRPC client that connects to a running instance of our provided [gRPC server](/rust/grpc-server).

## Building

`Makefile` at the repo root takes care of everything, but essentially you'll need the following to build the code:
 - The compiled protobuf definitions (with the auto-generated client implementation)
 - The [service](/rust/grpc-server) binaries for your platform, so `go:embed` directives can find them.

## Usage

```
$ go get github.com/dusk-network/bls12_381-sign/go/grpc/bls
```

This package exports the following methods:

```go
Connect()
Disconnect()
GenerateKeys() ([]byte, []byte)
Sign(sk, pk, msg []byte) ([]byte, error)
Verify(apk, sig, msg []byte) error
CreateApk(pk []byte) ([]byte, error)
AggregatePk(apk []byte, pks ...[]byte) ([]byte, error)
AggregateSig(sig []byte, sigs ...[]byte) ([]byte, error)
````

Please check [`bls_test.go`](/go/grpc/bls/bls_test.go) for a few examples.