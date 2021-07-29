#!/bin/sh

cargo build --release
gcc bp7-test.c -I ../../target -L../../target/release -lbp7 -static -lpthread -ldl -O2 -o bp7-test

