# bp7-rs

[![Crates.io](https://img.shields.io/crates/v/bp7.svg)](https://crates.io/crates/bp7)
[![Docs.rs](https://docs.rs/bp7/badge.svg)](https://docs.rs/bp7)
[![Build status](https://api.travis-ci.org/dtn7/bp7-rs.svg?branch=master)](https://travis-ci.org/dtn7/bp7-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Rust implementation of dtn bundle protocol 7 draft https://tools.ietf.org/html/draft-ietf-dtn-bpbis-31

This library only handles encoding and decoding of bundles, not transmission or other processing of the data. A full daemon using this library can be found here: https://github.com/dtn7/dtn7-rs

## Benchmarking

A simple benchmark is shipped with the library. It (de)serializes Bundles with a primary block, bundle age block and a payload block with the contents (`b"ABC"`). This benchmark can be used to compare the rust implementation to the golang, python or java implementations. 

```
cargo run --release --example benchmark
    Finished release [optimized] target(s) in 0.29s
     Running `target/release/examples/benchmark`
Creating 100000 bundles with CRC_NO: 	510059 bundles/second
Creating 100000 bundles with CRC_16: 	293399 bundles/second
Creating 100000 bundles with CRC_32: 	291399 bundles/second
Encoding 100000 bundles with CRC_NO: 	1090996 bundles/second
Encoding 100000 bundles with CRC_16: 	436836 bundles/second
Encoding 100000 bundles with CRC_32: 	432774 bundles/second
Loading 100000 bundles with CRC_NO: 	564817 bundles/second
Loading 100000 bundles with CRC_16: 	473768 bundles/second
Loading 100000 bundles with CRC_32: 	462013 bundles/second
```

These numbers were generated on a MBP 13" 2018 with i5 CPU and 16GB of ram.

## bp7 helper tool

For debugging a small helper tool is shipped providing basic functionality such as:
- random bundle generation (as hex and raw bytes)
- encoding of standard bundles (as hex and raw bytes)
- decoding of bundles (from hex and raw bytes)
- exporting raw payload of decoded bundles
- time conversion helpers


Some examples are given in the following shell session:
```
$ cargo install bp7
[...]
$ bp7
usage "bp7" <cmd> [args]
         encode <manifest> <payloadfile | - > [-x] - encode bundle and output raw bytes or hex string (-x)
         decode <hexstring | - > [-p] - decode bundle or payload only (-p)
         dtntime [dtntimestamp] - prints current time as dtntimestamp or prints dtntime human readable
         d2u [dtntimestamp] - converts dtntime to unixstimestamp
         rnd [-r] - return a random bundle either hexencoded or raw bytes (-r)
$ bp7 rnd
dtn://node81/files-680971330872-0
9f88071a000200040082016e2f2f6e6f646531382f7e74656c6582016e2f2f6e6f646538312f66696c657382016e2f2f6e6f646538312f66696c6573821b0000009e8d0de538001a0036ee80850a020000448218200085010100004443414243ff

$ bp7 decode 9f88071a000200040082016e2f2f6e6f646531382f7e74656c6582016e2f2f6e6f646538312f66696c657382016e2f2f6e6f646538312f66696c6573821b0000009e8d0de538001a0036ee80850a020000448218200085010100004443414243ff

[src/main.rs:101] &bndl = Bundle {
    primary: PrimaryBlock {
        version: 7,
        bundle_control_flags: 131076,
        crc: CrcNo,
        destination: Dtn(
            1,
            DtnAddress(
                "//node18/~tele",
            ),
        ),
        source: Dtn(
            1,
            DtnAddress(
                "//node81/files",
            ),
        ),
        report_to: Dtn(
            1,
            DtnAddress(
                "//node81/files",
            ),
        ),
        creation_timestamp: CreationTimestamp(
            680971330872,
            0,
        ),
        lifetime: 3600s,
        fragmentation_offset: 0,
        total_data_length: 0,
    },
    canonicals: [
        CanonicalBlock {
            block_type: 10,
            block_number: 2,
            block_control_flags: 0,
            crc: CrcNo,
            data: HopCount(
                32,
                0,
            ),
        },
        CanonicalBlock {
            block_type: 1,
            block_number: 1,
            block_control_flags: 0,
            crc: CrcNo,
            data: Data(
                [
                    65,
                    66,
                    67,
                ],
            ),
        },
    ],
}

$ echo -e "source=dtn://node1/bla\ndestination=dtn://node2/incoming\nlifetime=1h" > /tmp/out.manifest
$ echo "hallo welt" | bp7 encode /tmp/out.manifest - -x
9f880700008201702f2f6e6f6465322f696e636f6d696e6782016b2f2f6e6f6465312f626c61820100821b0000009e8d137d23001a0036ee8085010100004c4b68616c6c6f2077656c740aff

$ bp7 decode 9f880700008201702f2f6e6f6465322f696e636f6d696e6782016b2f2f6e6f6465312f626c61820100821b0000009e8d137d23001a0036ee8085010100004c4b68616c6c6f2077656c740aff -p
hallo welt

```

The generated hex string can also be directly discplayed as raw cbor on the awesome cbor.me website, e.g. http://cbor.me/?bytes=9f88071a000200040082016e2f2f6e6f646531382f7e74656c6582016e2f2f6e6f646538312f66696c657382016e2f2f6e6f646538312f66696c6573821b0000009e8d0de538001a0036ee80850a020000448218200085010100004443414243ff

## ffi support

The library can be used as a shared library or statically linked into other apps. 
When building `bp7` the corresponding C header is generated in `target/bp7.h`. 
Example usages for Linux with C calling `bp7` as well as nodejs can be found in `test/ffi`.

## wasm support [defunct, unmaintained stdweb crate]

The library should build for wasm even though only very few functions get exported. The example benchmark can also be used in the browser through the `cargo-web` crate:
```
cargo web start --target wasm32-unknown-unknown --example benchmark --release
```

Results should be shown in the javascript console on http://127.0.0.1:8000.

The performance is quite similar to the native performance:
```
Creating 100000 bundles with CRC_NO: 	441696 bundles/second
Creating 100000 bundles with CRC_16: 	416484 bundles/second
Creating 100000 bundles with CRC_32: 	405022 bundles/second
Encoding 100000 bundles with CRC_NO: 	1647039 bundles/second
Encoding 100000 bundles with CRC_16: 	908059 bundles/second
Encoding 100000 bundles with CRC_32: 	867603 bundles/second
Loading 100000 bundles with CRC_NO: 	401727 bundles/second
Loading 100000 bundles with CRC_16: 	388394 bundles/second
Loading 100000 bundles with CRC_32: 	384186 bundles/second
```

Some functions can easily be used from javascript (`cargo web deploy --release`):
```javascript
Rust.bp7.then(function(bp7) {
  var b = bp7.rnd_bundle_now(); 
  var enc = bp7.encode_to_cbor(b); 
  var payload = bp7.payload_from_bundle(b)
  console.log(payload); 
  console.log(String.fromCharCode.apply(null, payload));
  console.log(bp7.cbor_is_administrative_record(enc)); 
  console.log(bp7.sender_from_cbor(enc)); 
  console.log(bp7.recipient_from_bundle(b)); 
  console.log(bp7.valid_bundle(b)); 
});
```

Note that at the moment all functions have a variant working on the binary bundle and one working on the decoded bundle struct.

### Acknowledging this work

If you use this software in a scientific publication, please cite the following paper:

```BibTeX
@INPROCEEDINGS{baumgaertner2019bdtn7,
  author={L. {Baumgärtner} and J. {Höchst} and T. {Meuser}},
  booktitle={2019 International Conference on Information and Communication Technologies for Disaster Management (ICT-DM)},
  title={B-DTN7: Browser-based Disruption-tolerant Networking via Bundle Protocol 7},
  year={2019},
  volume={},
  number={},
  pages={1-8},
  keywords={Protocols;Browsers;Software;Convergence;Servers;Synchronization;Wireless fidelity},
  doi={10.1109/ICT-DM47966.2019.9032944},
  ISSN={2469-8822},
  month={Dec},
}
```

### License


Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.


Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in bp7-rs by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
