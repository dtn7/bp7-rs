# bp7-rs

[![Crates.io](https://img.shields.io/crates/v/bp7.svg)](https://crates.io/crates/bp7)
[![Docs.rs](https://docs.rs/bp7/badge.svg)](https://docs.rs/bp7)

Rust implementation of dtn bundle protocol 7 draft https://tools.ietf.org/html/draft-ietf-dtn-bpbis-13

This library only handles encoding and decoding of bundles, not transmission or other processing of the data.

This is more or less a port of the dtn7 golang implementation: https://github.com/dtn7/dtn7

**This code is not production ready!**

## Benchmarking

A simple benchmark is shipped with the library. It (de)serializes Bundles with a primary block, bundle age block and a payload block with the contents (`b"ABC"`). This benchmark can be used to compare the rust implementation to the golang, python or java implementations. 

```
cargo run --release --example benchmark
    Finished release [optimized] target(s) in 0.29s
     Running `target/release/examples/benchmark`
Creating 100000 bundles with CRC_NO: 	205058 bundles/second
Creating 100000 bundles with CRC_16: 	175278 bundles/second
Creating 100000 bundles with CRC_32: 	175840 bundles/second
Encoding 100000 bundles with CRC_NO: 	347518 bundles/second
Encoding 100000 bundles with CRC_16: 	252950 bundles/second
Encoding 100000 bundles with CRC_32: 	256585 bundles/second
Loading 100000 bundles with CRC_NO: 	363863 bundles/second
Loading 100000 bundles with CRC_16: 	316386 bundles/second
Loading 100000 bundles with CRC_32: 	322102 bundles/second
```

These numbers were generated on a MBP 13" 2018 with i5 CPU and 16GB of ram.
