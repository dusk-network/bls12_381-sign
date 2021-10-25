# Implementation of [BLS signatures](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html) using the BLS12-381 curve.

This implementation currently only supports rogue-key attack resistant batching, and does not support distinct message
verification.

There is also a gRPC/Protobuf microservice that can be turned on using a switch function. At this point the Cgo version
is better but there may be further work done that improves throughput, initial experiments show potential to reduce
processing time between 20-50%.

## Benchmarks

### Machine specs

The benchmarks were run on a Lenovo Ideapad 3 15" laptop with 2.1ghz Ryzen 5 CPU.

CPU:

```
$ lscpu
AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx
```

RAM:
```
9.9Gb DDR4 2400mhz (remainder to 12gb used for Vega GPU)
```

### Results

```
test benches::bench_aggregate_pk    ... bench:   1,722,810 ns/iter (+/- 251,791)
test benches::bench_aggregate_sig   ... bench:      45,407 ns/iter (+/- 5,259)
test benches::bench_sign            ... bench:   1,724,517 ns/iter (+/- 272,450)
test benches::bench_sign_vulnerable ... bench:   1,181,558 ns/iter (+/- 144,819)
test benches::bench_verify          ... bench:   4,546,850 ns/iter (+/- 970,595)
```
