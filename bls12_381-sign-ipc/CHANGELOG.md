# Change log

## 2021-10-19

Due to the slow execution and mysterious factors involved with Cgo, a gRPC/Protobuf service was created to provide this
EC signature library accessibility from Go (specifically `dusk-blockchain`), with the intention to explore improvements
over the Cgo implementation.

It's pretty much your bog-standard microservice, and reasonable efforts have been made to ensure that it is not causing
excessive delays in processing. Some work has shown that we may be able to greatly improve performance (maybe up to 50%
execution time) by dodging checks on conversions of keys, specifically Public Keys and Aggregated Public Keys, which is
being worked on in parallel to this.

It is still slower than the Cgo implementation as at release, but further work is being done to make it better, and
already we have seen improvements between 20-50% on benchmarks.

I'm not sure what else can be said about the code in the repository here. A macro was used to eliminate 2- and 3-level
unwraps from result types and enable immediate return on error, derived from the stdlib, and modified for the specific
purpose of fixed length slices. Other than that, it simply implements all the calls with as little processing as
possible.

The rest of the work that is integral to what has been done here is in `bls12_381-sign-go` which is the library that
consumes this service and provides access to Go applications. From its benchmarks, it appears that memory management in
Go is the main bottleneck. We have considered and partially completed an implementation that uses Capn Proto instead,
but this is waiting on the possible performance improvements by avoiding redundant checks with the gRPC/Protobuf
implementation.