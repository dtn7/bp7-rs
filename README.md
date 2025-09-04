# bp7-rs

[![Crates.io](https://img.shields.io/crates/v/bp7.svg)](https://crates.io/crates/bp7)
[![Docs.rs](https://docs.rs/bp7/badge.svg)](https://docs.rs/bp7)
[![Build status](https://api.travis-ci.org/dtn7/bp7-rs.svg?branch=master)](https://travis-ci.org/dtn7/bp7-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Chat](https://img.shields.io/matrix/dtn7:matrix.org)](https://matrix.to/#/#dtn7:matrix.org)


Rust implementation of dtn Bundle Protocol Version 7 ([RFC 9171](https://datatracker.ietf.org/doc/rfc9171/))

This library only handles encoding and decoding of bundles, not transmission or other processing of the data. 
A full daemon using this library can be found here: https://github.com/dtn7/dtn7-rs

Through the provided FFI interface, this library can also be used from C/C++, nodejs or flutter.

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
        benchmark - run a simple benchmark encoding/decoding bundles
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

This library only handles encoding and decoding of bundles, not transmission or other processing of the data.

The library can be used as a shared library or statically linked into other apps. 
With the help of `cbindgen` (`cargo install cbindgen`) the header file for this crate can be generated:
```
$ cbindgen -c cbindgen.toml > target/bp7.h
```

Example usages for Linux with C calling `bp7` as well as nodejs can be found in `examples/ffi`.

## WebAssembly Support

The library provides WebAssembly support and automatically builds JavaScript bindings when targeting any `wasm32-*` platform.

### Quick Start

Install `wasm-pack` if you haven't already:
```bash
cargo install wasm-pack
```

Build for your target platform (see [`wasm-pack` documentation](https://drager.github.io/wasm-pack/book/commands/build.html) for details):
```bash
# For web browsers
wasm-pack build --target web --out-dir pkg-web

# For Node.js
wasm-pack build --target nodejs --out-dir pkg-node
```

### Available Functions

The WASM module exports these functions (all return `Result<T, JsValue>` for proper error handling):

**Bundle Creation:**
- `new_std_bundle_now(src, dst, payload)` - Create standard bundle with current timestamp
- `rnd_bundle_now()` - Create random bundle for testing

**Encoding/Decoding:**
- `encode_to_cbor(bundle)` - Encode bundle to CBOR bytes
- `decode_from_cbor(bytes)` - Decode CBOR bytes to bundle

**Metadata Extraction:**
- `bid_from_bundle(bundle)` / `bid_from_cbor(bytes)` - Get bundle ID
- `sender_from_bundle(bundle)` / `sender_from_cbor(bytes)` - Get sender address
- `recipient_from_bundle(bundle)` / `recipient_from_cbor(bytes)` - Get recipient address
- `timestamp_from_bundle(bundle)` / `timestamp_from_cbor(bytes)` - Get creation timestamp
- `payload_from_bundle(bundle)` / `payload_from_cbor(bytes)` - Extract payload bytes

**Validation:**
- `valid_bundle(bundle)` / `valid_cbor(bytes)` - Validate bundle structure and lifetime
- `bundle_is_administrative_record(bundle)` / `cbor_is_administrative_record(bytes)` - Check if bundle is administrative

### JavaScript/Browser Usage

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>bp7-rs WASM Example</title>
</head>
<body>
    <script type="module">
        import init, * as bp7 from './pkg-web/bp7.js';
        
        async function run() {
            await init();
            
            // Create a bundle
            const bundle = bp7.new_std_bundle_now(
                "dtn://sender/app",
                "dtn://receiver/app", 
                "Hello from the browser!"
            );
            
            // Extract metadata
            const bundleId = bp7.bid_from_bundle(bundle);
            const sender = bp7.sender_from_bundle(bundle);
            const recipient = bp7.recipient_from_bundle(bundle);
            const timestamp = bp7.timestamp_from_bundle(bundle);
            const payload = bp7.payload_from_bundle(bundle);
            const isAdmin = bp7.bundle_is_administrative_record(bundle);
            
            console.log(`Bundle: ${bundleId}`);
            console.log(`Route: ${sender} → ${recipient}`);
            console.log(`Created: ${timestamp}`);
            console.log(`Payload: "${new TextDecoder().decode(new Uint8Array(payload))}"`);
            console.log(`Administrative: ${isAdmin}`);
            
            // CBOR operations
            const cborBytes = bp7.encode_to_cbor(bundle);
            const isValid = bp7.valid_cbor(cborBytes);
            
            console.log(`CBOR: ${cborBytes.length} bytes, valid: ${isValid}`);
            
            // Decode and verify roundtrip
            const decoded = bp7.decode_from_cbor(cborBytes);
            const decodedId = bp7.bid_from_bundle(decoded);
            console.log(`Roundtrip success: ${bundleId === decodedId}`);
        }
        
        run().catch(console.error);
    </script>
</body>
</html>
```

### Node.js Usage

```javascript
const bp7 = require('./pkg-node');

async function example() {
    // Create a bundle
    const bundle = bp7.new_std_bundle_now(
        "dtn://sender/app",
        "dtn://receiver/app", 
        "Hello from Node.js!"
    );
    
    // Extract metadata
    const bundleId = bp7.bid_from_bundle(bundle);
    const sender = bp7.sender_from_bundle(bundle);
    const recipient = bp7.recipient_from_bundle(bundle);
    const timestamp = bp7.timestamp_from_bundle(bundle);
    const payload = bp7.payload_from_bundle(bundle);
    const isAdmin = bp7.bundle_is_administrative_record(bundle);
    
    console.log(`Bundle: ${bundleId}`);
    console.log(`Route: ${sender} → ${recipient}`);
    console.log(`Created: ${timestamp}`);
    console.log(`Payload: "${new TextDecoder().decode(new Uint8Array(payload))}"`);
    console.log(`Administrative: ${isAdmin}`);
    
    // CBOR operations
    const cborBytes = bp7.encode_to_cbor(bundle);
    const isValid = bp7.valid_cbor(cborBytes);
    
    console.log(`CBOR: ${cborBytes.length} bytes, valid: ${isValid}`);
    
    // Decode and verify roundtrip
    const decoded = bp7.decode_from_cbor(cborBytes);
    const decodedId = bp7.bid_from_bundle(decoded);
    console.log(`Roundtrip success: ${bundleId === decodedId}`);
}

example().catch(console.error);
```

### WASI Support & Benchmarking

For server-side WASI environments, install the WASI runtime:

```bash
cargo install wasmtime-cli
```

Build and run WASI applications:
```bash
# Build for WASI
cargo build --target wasm32-wasip1 --release --example benchmark

# Run with wasmtime
wasmtime run target/wasm32-wasip1/release/examples/benchmark.wasm
```

Example WASI benchmark performance:
```
Creating 100000 bundles with CRC_NO:             511956 bundles/second
Creating 100000 bundles with CRC_16:             147850 bundles/second
Creating 100000 bundles with CRC_32:             145072 bundles/second
Encoding 100000 bundles with CRC_NO:            1072625 bundles/second
Encoding 100000 bundles with CRC_16:             450680 bundles/second
Encoding 100000 bundles with CRC_32:             447624 bundles/second
Loading 100000 bundles with CRC_NO:              520731 bundles/second
Loading 100000 bundles with CRC_16:              231351 bundles/second
Loading 100000 bundles with CRC_32:              230073 bundles/second
```

### Feature Flags

For WASM targets, the library provides a `wasm-js` feature flag that enables proper randomness support via getrandom's `wasm_js` backend. Following [getrandom's recommendations](https://docs.rs/getrandom/latest/getrandom/#webassembly-support), this feature is included in the default feature set for convenience, but can be disabled for library users who want to choose their own `getrandom` backend.

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
