# Wrapper library for CGo and gRPC calls to [dusk-bls12_381-sign](https://github.com/dusk-network/bls12_381-sign)

This library provides wrapper functions which make CGo calls to the BLS 
signature crate linked above, as well as instead running it as a service and 
directing calls through this route.

## Building

To obtain the `dusk-bls12_381-sign` library, run:

```
make build
```

This will create the static C library for you and link it with the Go binary 
via cgo, as well as the microservice binary, and last but not least, 
generates the Go grpc/protobuf which is placed in `bls/proto/bls12381sig.pb.go`.

The generated code is used by the functions in ipc*.go to encode requests 
and decode responses from the Rust gRPC protobuf service that runs to 
provide the API in this mode.

## Testing

```
make test
```

## Benchmarks

### Running

```
make bench
```

For a more advanced output use:

```
make benchmem
```

### Machine specs

The benchmarks were run on a 2020 Lenovo Ideapad 3 15ADA05 laptop with 9.6gb of DDR2400 memory (remainder dedicated to
GPU).

### Results

```
BenchmarkSign-8                     1592           3679795 ns/op              48 B/op          1 allocs/op
BenchmarkVerify-8                    842           7047458 ns/op               0 B/op          0 allocs/op
BenchmarkAggregatePk-8              1087           7759776 ns/op             216 B/op          3 allocs/op
BenchmarkAggregateSig-8             3801           2020535 ns/op             120 B/op          3 allocs/op
BenchmarkSwitchToIPC-8          1000000000               0.5005 ns/op          0 B/op          0 allocs/op
BenchmarkSignIPC-8                   961           6300115 ns/op            5321 B/op         95 allocs/op
BenchmarkVerifyIPC-8                 591          12450438 ns/op            5210 B/op         94 allocs/op
BenchmarkAggregatePkIPC-8            517          10337759 ns/op            5390 B/op         96 allocs/op
BenchmarkAggregateSigIPC-8          3036           1951072 ns/op            5198 B/op         96 allocs/op
```

The baseline for these results with the Rust version:

```
test benches::bench_aggregate_pk    ... bench:   1,748,285 ns/iter (+/- 400,954)
test benches::bench_aggregate_sig   ... bench:      46,985 ns/iter (+/- 16,819)
test benches::bench_sign            ... bench:   1,993,845 ns/iter (+/- 699,657)
test benches::bench_sign_vulnerable ... bench:   1,182,060 ns/iter (+/- 634,274)
test benches::bench_verify          ... bench:   5,261,980 ns/iter (+/- 1,509,594)

```