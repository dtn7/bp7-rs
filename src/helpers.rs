use crate::{bundle, dtntime, eid};
use core::num::ParseIntError;
use nanorand::{WyRand, RNG};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_arch = "wasm32"))]
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
pub fn unix_timestamp() -> u64 {
    (stdweb::web::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_millis() as u64
}

#[cfg(target_arch = "wasm32")]
pub fn ts_ms() -> u64 {
    (stdweb::web::Date::now()) as u64
}

/// Convert byte slice into a hex string
pub fn hexify(buf: &[u8]) -> String {
    let mut hexstr = String::new();
    for &b in buf {
        hexstr.push_str(&format!("{:02x?}", b));
    }
    hexstr
}
/// Convert a hex string into a byte vector
pub fn unhexify(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
#[cfg(feature = "json")]
pub fn ser_dump<T: serde::ser::Serialize>(input: &T, hr: &str) {
    println!("Description | Value");
    println!("--- | ---");
    println!("human-readable | {}", hr);
    let json = serde_json::to_string(input).unwrap();
    println!("json | `{}`", json);
    let cbor = serde_cbor::to_vec(input).unwrap();
    println!(
        "hex string | [`{}`](http://cbor.me/?bytes={})",
        hexify(&cbor),
        hexify(&cbor)
    );
    println!("byte array | `{:?}`\n", cbor);
}
#[cfg(feature = "json")]
pub fn vec_dump<T: serde::ser::Serialize>(input: &T, cbor: Vec<u8>, hr: &str) {
    println!("Description | Value");
    println!("--- | ---");
    println!("human-readable | {}", hr);
    let json = serde_json::to_string(input).unwrap();
    println!("json | `{}`", json);
    println!(
        "hex string | [`{}`](http://cbor.me/?bytes={})",
        hexify(&cbor),
        hexify(&cbor)
    );
    println!("byte array | `{:?}`\n", cbor);
}
pub fn rnd_bundle(now: dtntime::CreationTimestamp) -> bundle::Bundle {
    let mut rng = WyRand::new();
    let singletons = vec!["sms", "files", "123456", "incoming", "mavlink"];
    let groups = vec!["~news", "~tele", "~mavlink"];
    //rng.shuffle(&mut singletons);
    //rng.shuffle(&mut groups);
    let concatenated = [&singletons[..], &groups[..]].concat();
    //rng.shuffle(&mut concatenated);
    let dst_string = format!(
        "//node{}/{}",
        rng.generate_range::<u32>(1, 99),
        concatenated[rng.generate_range::<usize>(0, concatenated.len())]
    );
    let src_string = format!(
        "//node{}/{}",
        rng.generate_range::<u32>(1, 99),
        singletons[rng.generate_range::<usize>(0, singletons.len())]
    );
    let dst = eid::EndpointID::with_dtn(&dst_string).unwrap();
    let src = eid::EndpointID::with_dtn(&src_string).unwrap();
    //let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);;
    //let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);;
    let mut b = bundle::new_std_payload_bundle(src, dst, b"ABC".to_vec());
    b.primary.creation_timestamp = now;
    b
}
