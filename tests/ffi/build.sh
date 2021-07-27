#!/bin/sh

cargo build
gcc bp7-test.c -I ../../include -L../../target/debug -lbp7 -static -lpthread -ldl -o bp7-test

