use super::*;
use core::num::ParseIntError;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_arch = "wasm32"))]
pub fn get_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
pub fn get_unix_timestamp() -> u64 {
    (stdweb::web::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_ts_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_millis()
}

#[cfg(target_arch = "wasm32")]
pub fn get_ts_ms() -> u128 {
    (stdweb::web::Date::now()) as u128
}

pub fn hexify(buf: &[u8]) -> String {
    let mut hexstr = String::new();
    for &b in buf {
        hexstr.push_str(&format!("{:02x?}", b));
    }
    hexstr
}
pub fn unhexify(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn rnd_bundle(now: dtntime::CreationTimestamp) -> bundle::Bundle {
    let mut rng = rand::thread_rng();
    let dst_string = format!("node{}/inbox", rng.gen_range(1, 4));
    let src_string = format!("node{}/inbox", rng.gen_range(1, 4));
    let dst = eid::EndpointID::with_dtn(&dst_string);
    let src = eid::EndpointID::with_dtn(&src_string);
    //let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);;
    //let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);;

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(60 * 60 * 1_000_000)
        .build()
        .unwrap();

    let mut b = bundle::BundleBuilder::default()
        .primary(pblock)
        .canonicals(vec![
            canonical::new_payload_block(0, b"ABC".to_vec()),
            canonical::new_bundle_age_block(1, 0, 0),
        ])
        .build()
        .unwrap();
    b.set_crc(crc::CRC_16);
    b.calculate_crc();

    b
}
