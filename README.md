# BLS12-381 Curve Signature

This repo contains Dusk Network's [implementation](https://github.com/bls12_381-sign/rust/bls12_381-sign) of the BLS Signatures using the BLS12-381 curve

## Go

Two options are provided to work with the library from Go:

1. Using unix sockets for IPC communication through GRPC with a rust service that calls the library.
2. Using cgo bindings to interface directly with the library binaries.

## TBC...