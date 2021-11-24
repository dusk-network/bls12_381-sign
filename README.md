# BLS12-381 Curve Signature

This repo contains Dusk Network's [implementation](https://github.com/bls12_381-sign/rust/bls12_381-sign) of the BLS Signatures using the BLS12-381 curve. This implementation currently only supports rogue-key attack resistant batching, and does not support distinct message verification.

## Rust

The [library](https://github.com/bls12_381-sign/rust/bls12_381-sign) is written in rust.

We also provide a sample IPC [micro-service](https://github.com/bls12_381-sign/rust/grpc-server) that provides a synchronous gRPC interface to the library for third-party clients.

## Go

We provide a couple options to work with the library using Go:

1. [Using CGo](https://github.com/bls12_381-sign/go/cgo/bls) to build and link directly to the lib binaries.
1. [Using gRPC](https://github.com/bls12_381-sign/go/grpc/bls) to communicate with our simple lib IPC server.

## Benchmarks

We've found the CGo version to perform faster with `Go 1.17+`

Recent benchmarks are attached for reference:

### CGo
```
cpu: Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
BenchmarkSign              	    1264	   4416508 ns/op	      48 B/op	       1 allocs/op
BenchmarkVerify            	     706	   8568588 ns/op	       0 B/op	       0 allocs/op
BenchmarkAggregatePk       	     864	   6687951 ns/op	     216 B/op	       3 allocs/op
BenchmarkAggregateSig      	    4274	   1443901 ns/op	     120 B/op	       3 allocs/op
```

### gRPC

```
BenchmarkSign           	    1317	   4507956 ns/op	    5317 B/op	      95 allocs/op
BenchmarkVerify         	     693	   8767921 ns/op	    5207 B/op	      94 allocs/op
BenchmarkAggregatePk    	     656	   9209897 ns/op	    5385 B/op	      96 allocs/op
BenchmarkAggregateSig   	    3651	   1645111 ns/op	    5194 B/op	      96 allocs/op
```