## Dependencies

- `sudo apt install build-essential binutils-dev libunwind-dev lldb`
- `cargo install honggfuzz`

## Inspecting crahes in debugger

`cargo hfuzz run-debug hfuzz-bp7 hfuzz_workspace/hfuzz-bp7/*.fuzz`
