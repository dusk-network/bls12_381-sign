as at commit a1c5021003b059dc4312df47c05ff32c1d93694c
```
test benches::bench_aggregate_pk    ... bench:   1,711,562 ns/iter (+/- 2,051,174)
test benches::bench_aggregate_sig   ... bench:      93,024 ns/iter (+/- 87,493)
test benches::bench_sign            ... bench:   2,008,175 ns/iter (+/- 1,959,587)
test benches::bench_sign_vulnerable ... bench:   1,187,762 ns/iter (+/- 1,482,829)
test benches::bench_verify          ... bench:   5,203,645 ns/iter (+/- 5,672,643)
```
first cleanup
```
test benches::bench_aggregate_pk    ... bench:   1,698,695 ns/iter (+/- 456,131)
test benches::bench_aggregate_sig   ... bench:      46,209 ns/iter (+/- 7,621)
test benches::bench_sign            ... bench:   1,716,675 ns/iter (+/- 312,170)
test benches::bench_sign_vulnerable ... bench:   1,151,095 ns/iter (+/- 133,153)
test benches::bench_verify          ... bench:   4,413,040 ns/iter (+/- 742,624)
```