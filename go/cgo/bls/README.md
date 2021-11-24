# CGo Wrapper for BLS12-381 Sign

`bls.go` exposes a CGo wrapper to the native rust [bls12-381 signing library](https://github.com/dusk-network/bls12_381-sign/rust/bls12_381-sign).

## Building

`Makefile` at the repo root takes care of everything, but essentially you'll want to have the built lib binaries in this directory for GCC to link against them as specified in the CGo headers at the top of `bls.go`. We provide pre-built binaries for Ubuntu and Darwin for convenience.

## Usage

```
$ go get github.com/dusk-network/bls12_381-sign/go/cgo/bls
```

This package exports the following methods:

```go
GenerateKeys() ([]byte, []byte)
GenerateKeysWithRaw() ([]byte, []byte, []byte) 
Sign(sk, pk, msg []byte) ([]byte, error)
Verify(apk, sig, msg []byte) error
CreateApk(pk []byte) ([]byte, error)
AggregatePk(apk []byte, pks ...[]byte) ([]byte, error)
AggregatePKsUnchecked(pks ...[]byte) ([]byte, error)
AggregateSig(sig []byte, sigs ...[]byte) ([]byte, error)
PkToRaw(pk []byte) ([]byte, error)
````

Please check [`bls_test.go`](https://github.com/dusk-network/bls12_381-sign/go/cgo/bls/bls_test.go) for a few examples.