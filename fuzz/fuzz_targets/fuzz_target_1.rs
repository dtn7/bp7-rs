#![no_main]
use bp7::*;
use libfuzzer_sys::fuzz_target;
use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    let deserialized: std::result::Result<Bundle, _> = Bundle::try_from(Vec::from(data));
    if deserialized.is_ok() {
        deserialized.unwrap().validate();
    }
});
