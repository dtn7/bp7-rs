# Changelog
All notable changes to this project will be documented in this file.

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
