# Changelog
All notable changes to this project will be documented in this file.

## [0.12.0] - 2026-10-17

### Bug Fixes

- Bcbs follow the block constraints of RFC 9172
- Reject reserved integrity scope flags at the security source
- Bibs must not target security blocks
- Security operations are unique per target
- Interactions of bibs and bcbs follow RFC 9172
- Encrypted bibs are not decoded
- Security targets must exist in the bundle

### Features

- Block confidentiality blocks and BCB-AES-GCM parameters
- BCB-AES-GCM encryption and decryption
- AES key wrap for the keys of RFC 9173 security contexts
- Decrypt BCBs with the authentication tag in the ciphertext
- IPPT for the primary block as security target
- Sign and verify bundles with BIB-HMAC-SHA2
- Support IVs of 8 to 16 bytes for BCB-AES-GCM
- Add bpsec status report reason codes
- Security acceptors restore target crcs
- Optionally append the bcb authentication tag to the ciphertext
- Remove security operations of removed blocks
- Split security operations off a bib
- Encrypt bibs and multiple targets with bcbs

### Refactor

- Split up bpsec and default security context definitions
- Generic abstract security block for all security contexts

### Testing

- Creation timestamp doctest is not flaky at millisecond boundaries

## [0.11.0] - 2026-10-17

### Bug Fixes

- Unknown crc types no longer panic during crc calculation
- Eid decoder now rejects malformed dtn addresses
- Integrity block decoder no longer panics on malformed input
- Hop count increase no longer overflows at u8::MAX
- Lifetime check no longer overflows for huge lifetimes
- Status reports for fragments no longer panic
- Bundles with more than 22 canonical blocks are encoded correctly
- Ffi functions return null instead of panicking on invalid input
- Ffi free functions release all memory
- Integrity blocks are decoded from their RFC 9172 encoding
- Bib protection of the primary block checks block number 0
- Reserved control flag bits are detected
- Creation timestamps stay unique across threads and 32 bit targets
- Bundle age is compared to the lifetime in milliseconds
- Primary block fragment fields are decoded based on the fragment flag
- Optional status report fields are decoded for indefinite-length arrays
- Unhexify reports invalid input instead of panicking
- Bundle age update saturates instead of panicking
- Eid decoder rejects dtn:none encoded as negative integer
- Canonical blocks with block number zero are invalid
- Bib context parameters are decoded by their id
- Integrity block builder only requires parameters if flagged
- Bib hmac computation and encoding no longer panic
- Bib hmac results use result id 1
- Ippt creation no longer prints to stdout

### Fix

- Zero timestamp w/ bundle age block validation (#7)
- Corrected wrong payload block number err msg (#9)

### Performance

- Use slice-by-16 lookup tables for crc calculation
- Calculate and check crcs without cloning or buffering blocks
- Encode bundles in a single pass
- Collect small writes before updating the crc digest
- Decode dtn endpoint ids without intermediate cbor value
- Create bundle ids and endpoint strings with fewer allocations
- Validate bundles without hash sets

### Styling

- Resolve clippy warnings

### Testing

- Benchmark encoding and decoding of large payloads
- Compile security tests only with the bpsec feature

## [0.10.7] - 2025-06-01

### Bug Fixes

- Fixed release.sh to also work on macos and use gnu sed
- Cleanup of bpsec tests, removed hex-literal crate
- Checking if the payload block is the last canonical block in the bundle. fixes #5
- Eid decoder now complains if dtn:none is encoded with a wrong integer

### Features

- Added initial BP security module (optional feature): With Block Integrity Block defined in RFC 9172 and a test case defined in RFC 9173 (#3)
- Bp7 cli tool now also validates decoded bundles and outputs potential errors. validate() now also checks crc (beware: internal clone for mutability)

### Miscellaneous Tasks

- Eid imports cleanup
- Updated various dependencies and pleased clippy

### Testing

- Fixed tests for correct payload position in canonical block list

## [0.10.6] - 2023-11-24

### Bug Fixes

- Calling node_id() on an IPN eid now returns correct URL instead of an dtn scheme formatted IPN address

### Documentation

- Added matrix badge to dtn7 space in README

### Miscellaneous Tasks

- Switched to most recent test-case crate, making "allow_result" feature obsolete
- Upgraded dependencies
- Pleased clippy
- Updated dependencies

### Refactor

- Replaced push_str with write in hexify helper, one less allocation

## [0.10.5] - 2022-02-10

### Features

- Load bundles from slices, no need for an owned copy

## [0.10.4] - 2022-02-07

### Bug Fixes

- Removed leftover dbg!() in canonical block deserializer
- Workaround for bug in upstream test-case crate (v1.2.2)

### Refactor

- Use println! instead of dbg! in CLI for printing decoded bundles

### Testing

- Added tests for bundle ID and bundle ToString functionality

## [0.10.2] - 2022-02-05

### Bug Fixes

- Fixed a bug where payload data was double encoded

## [0.10.1] - 2022-02-04

### Bug Fixes

- With disabled default features the benchmark helpers did not work anymore. now they have the feature 'benchmark-helpers'

## [0.10.0] - 2022-02-04

### Bug Fixes

- Explictly drop CString references in bundle_metadata_free of ffi
- DtnAdress::new now adds '//' before node name
- Enforce trailing slash for endpoint IDs that are the node ID

## [0.9.3] - 2022-02-03

### Bug Fixes

- Validation now rejects bundles without payload
- Fixed build script of ffi example, adding -lm flag
- Marked extern C functions which can lead to UB as unsafe #2

### Documentation

- Updated all documentation to point to rfc 9171 instead of the draft

### Miscellaneous Tasks

- Updated flags and dtn URI parsing be in line with RFC 9171

## [0.9.2] - 2021-09-10

### Bug Fixes

- Require a payload block in a new bundle as described in Bundle Protocol Draft
- Changed unwraps into proper error handling

### Refactor

- Using bitflags for bundle and block control flags
- Eliminated derive_builder, added manual implementations

### Styling

- Pleased clippy in builder

### Build

- Updated Cargo.toml to be managed by release.sh

## [0.9.1] - 2021-09-09

### Refactor

- Eliminated derive_builder, added manual implementations

<!-- generated by git-cliff -->
