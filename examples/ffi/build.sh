#!/bin/sh

cargo build --release
cd ../..
cbindgen -c cbindgen.toml > target/bp7.h
cd examples/ffi
gcc bp7-test.c -I ../../target -L../../target/release -lbp7 -static -lpthread -ldl -O2 -o bp7-test

