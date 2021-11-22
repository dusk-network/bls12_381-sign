# CGo Wrapper for BLS12-381 Sign

`bls.go` exposes a CGo wrapper to the native rust [bls12-381 signing library](https://github.com/dusk-network/bls12_381-sign/rust/bls12_381-sign).

## Building

`Makefile` at the repo root takes care of everything, but essentially you'll want to have the built lib binaries in this directory for GCC to link against them as specified in the CGo headers at the top of `bls.go`. We provide pre-built binaries for Ubuntu and Darwin for convenience.

## Usage

This module exports all required methods to satisfy the [Bls12381Sign Interface](https://github.com/dusk-network/bls12_381-sign/go/bls.go). Please check `bls_test.go` for a few examples.