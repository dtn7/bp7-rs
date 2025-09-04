use crate::ByteBuffer;
use crate::{bundle, canonical, crc, dtntime, eid, flags::BlockControlFlags, primary, Bundle};

use core::num::ParseIntError;
use nanorand::{Rng, WyRand};
use std::convert::TryFrom;
use std::fmt::Write as _;
use std::io::{stdout, Write};
use web_time::{Instant, SystemTime, UNIX_EPOCH};

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_secs()
}

pub fn ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_millis() as u64
}

/// Convert byte slice into a hex string
pub fn hexify(buf: &[u8]) -> String {
    let mut hexstr = String::new();
    for &b in buf {
        let _ = write!(hexstr, "{:02x}", b);
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
    let singletons = ["sms", "files", "123456", "incoming", "mavlink"];
    let groups = ["~news", "~tele", "~mavlink"];
    //rng.shuffle(&mut singletons);
    //rng.shuffle(&mut groups);
    let concatenated = [&singletons[..], &groups[..]].concat();
    //rng.shuffle(&mut concatenated);
    let dst_string = format!(
        "//node{}/{}",
        rng.generate_range(1_u32..99),
        concatenated[rng.generate_range(0_usize..concatenated.len())]
    );
    let src_string = format!(
        "//node{}/{}",
        rng.generate_range(1_u32..99),
        singletons[rng.generate_range(0_usize..singletons.len())]
    );
    let dst = eid::EndpointID::with_dtn(&dst_string).unwrap();
    let src = eid::EndpointID::with_dtn(&src_string).unwrap();
    //let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);;
    //let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);;
    let mut b = bundle::new_std_payload_bundle(src, dst, b"ABC".to_vec());
    b.primary.creation_timestamp = now;
    b
}

pub fn get_bench_bundle(crc_type: crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("//node2/inbox").unwrap();
    let src = eid::EndpointID::with_dtn("//node1/123456").unwrap();
    //let dst = eid::EndpointID::with_ipn(eid::IpnAddress(1, 2));
    //let src = eid::EndpointID::with_ipn(eid::IpnAddress(2, 3));
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);
    //let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);

    //let pblock = primary::new_primary_block("dtn:node2/inbox".to_string(), "dtn:node1/123456".to_string(), now, 60 * 60 * 1_000_000);
    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(std::time::Duration::from_secs(60 * 60))
        .build()
        .unwrap();
    let cblocks = vec![
        canonical::new_bundle_age_block(
            2,                          // block number
            BlockControlFlags::empty(), // flags
            0,                          // time elapsed
        ),
        canonical::new_payload_block(BlockControlFlags::empty(), b"ABC".to_vec()),
    ];
    //let cblocks = Vec::new();
    let mut b = bundle::Bundle::new(pblock, cblocks);
    // bundle builder is significantly slower!
    /*let mut b = bundle::BundleBuilder::default()
    .primary(pblock)
    .canonicals(cblocks)
    .build()
    .unwrap();*/
    b.set_crc(crc_type);
    b.calculate_crc();
    b.validate().unwrap();
    b
}

pub fn bench_bundle_create(runs: i64, crc_type: crc::CrcRawType) -> Vec<ByteBuffer> {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    let mut bundles: Vec<ByteBuffer> = Vec::with_capacity(runs as usize);

    print!("Creating {} bundles with {}: \t", runs, crc_str);
    stdout().flush().unwrap();

    let bench_now = Instant::now();

    for _x in 0..runs {
        let mut b = get_bench_bundle(crc_type);
        let _serialized = b.to_cbor();
        //let _serialized = b.to_json();
        bundles.push(_serialized);
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{:>15} bundles/second", (runs as f64 / sec) as i64);
    bundles
}

pub fn bench_bundle_encode(runs: i64, crc_type: crc::CrcRawType) -> Vec<ByteBuffer> {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    let mut bundles: Vec<ByteBuffer> = Vec::with_capacity(runs as usize);
    //let mut bundles: Vec<String> = Vec::new();

    print!("Encoding {} bundles with {}: \t", runs, crc_str);
    stdout().flush().unwrap();

    let bench_now = Instant::now();

    let mut b = get_bench_bundle(crc_type);

    for _x in 0..runs {
        b.primary.lifetime += std::time::Duration::new(0, 1);
        let _serialized = b.to_cbor();
        //let _serialized = b.to_json();
        bundles.push(_serialized);
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{:>15} bundles/second", (runs as f64 / sec) as i64);
    bundles
}

pub fn bench_bundle_load(runs: i64, crc_type: crc::CrcRawType, mut bundles: Vec<ByteBuffer>) {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    print!("Loading {} bundles with {}: \t", runs, crc_str);
    stdout().flush().unwrap();

    let bench_now = Instant::now();
    for _x in 0..runs {
        let b = bundles.pop().unwrap();
        let _deserialized: Bundle = Bundle::try_from(b.as_slice()).unwrap();
        _deserialized.validate().unwrap();
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{:>15} bundles/second", (runs as f64 / sec) as i64);
}
