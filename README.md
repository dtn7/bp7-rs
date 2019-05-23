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
Creating 100000 bundles with CRC_NO: 	206964 bundles/second
Creating 100000 bundles with CRC_16: 	172704 bundles/second
Creating 100000 bundles with CRC_32: 	174935 bundles/second
Encoding 100000 bundles with CRC_NO: 	356908 bundles/second
Encoding 100000 bundles with CRC_16: 	259877 bundles/second
Encoding 100000 bundles with CRC_32: 	261549 bundles/second
Loading 100000 bundles with CRC_NO: 	598800 bundles/second
Loading 100000 bundles with CRC_16: 	500347 bundles/second
Loading 100000 bundles with CRC_32: 	497460 bundles/second
```

These numbers were generated on a MBP 13" 2018 with i5 CPU and 16GB of ram.

## bp7 helper tool

For debugging a small helper tool is shipped:
```
$ cargo install bp7
[...]
$ bp7
usage "bp7" <cmd> [args]
	decode <hexstring>
	rnd
$ bp7 rnd
9f8907000182016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f78821a247966ba001ad693a4004225b686010000014341424342237186080100010042dbccff

$ bp7 decode 9f8907000182016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f78821a247966ba001ad693a4004225b686010000014341424342237186080100010042dbccff

[src/main.rs:17] &bndl = Bundle {
    primary: PrimaryBlock {
        version: 7,
        bundle_control_flags: 0,
        crc_type: 1,
        destination: Dtn(
            1,
            "node3/inbox"
        ),
        source: Dtn(
            1,
            "node3/inbox"
        ),
        report_to: Dtn(
            1,
            "node3/inbox"
        ),
        creation_timestamp: CreationTimestamp(
            611935930,
            0
        ),
        lifetime: 3600000000,
        fragmentation_offset: 0,
        total_data_length: 0,
        crc: [
            37,
            182
        ]
    },
    canonicals: [
        CanonicalBlock {
            block_type: 1,
            block_number: 0,
            block_control_flags: 0,
            crc_type: 1,
            data: Data(
                [
                    65,
                    66,
                    67
                ]
            ),
            crc: [
                35,
                113
            ]
        },
        CanonicalBlock {
            block_type: 8,
            block_number: 1,
            block_control_flags: 0,
            crc_type: 1,
            data: BundleAge(
                0
            ),
            crc: [
                219,
                204
            ]
        }
    ]
}
```

The generated hex string can also be directly discplayed as raw cbor on the awesome cbor.me website, e.g. http://cbor.me/?bytes=9f8907000182016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f7882016b6e6f6465332f696e626f78821a247966ba001ad693a4004225b686010000014341424342237186080100010042dbccff
