use bp7::{bundle, canonical, crc, dtntime, eid, primary, Bundle, ByteBuffer};
use instant::Instant;
use std::convert::TryFrom;
use std::io::stdout;
use std::io::Write;

#[cfg(target_arch = "wasm32")]
use stdweb::*;

#[cfg(target_arch = "wasm32")]
macro_rules! print {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        js! {
            if(!window.tbuf) window.tbuf = "";
            window.tbuf += @{msg};
        }
    }}
}

#[cfg(target_arch = "wasm32")]
macro_rules! println {
    ($($tt:tt)*) => {{
        let msg = format!($($tt)*);
        js! {
            if(!window.tbuf) window.tbuf = "";
            console.log(window.tbuf + @{ msg });
            window.tbuf = "";
        }
    }}
}

const RUNS: i64 = 100_000;

fn get_bench_bundle(crc_type: crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox").unwrap();
    let src = eid::EndpointID::with_dtn("node1/123456").unwrap();
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
        canonical::new_payload_block(0, b"ABC".to_vec()),
        canonical::new_bundle_age_block(
            2, // block number
            0, // flags
            0, // time elapsed
        ),
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
    b.validate().unwrap();
    b
}

fn bench_bundle_create(runs: i64, crc_type: crc::CrcRawType) -> Vec<ByteBuffer> {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    let mut bundles: Vec<ByteBuffer> = Vec::with_capacity(runs as usize);

    print!("Creating {} bundles with {}: \t", RUNS, crc_str);
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

fn bench_bundle_encode(runs: i64, crc_type: crc::CrcRawType) -> Vec<ByteBuffer> {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    let mut bundles: Vec<ByteBuffer> = Vec::with_capacity(runs as usize);
    //let mut bundles: Vec<String> = Vec::new();

    print!("Encoding {} bundles with {}: \t", RUNS, crc_str);
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

fn bench_bundle_load(runs: i64, crc_type: crc::CrcRawType, mut bundles: Vec<ByteBuffer>) {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    print!("Loading {} bundles with {}: \t", RUNS, crc_str);
    stdout().flush().unwrap();

    let bench_now = Instant::now();
    for _x in 0..runs {
        let b = bundles.pop().unwrap();
        let _deserialized: Bundle = Bundle::try_from(b).unwrap();
        _deserialized.validate().unwrap();
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{:>15} bundles/second", (runs as f64 / sec) as i64);
}
fn main() {
    let crcno = bench_bundle_create(RUNS, crc::CRC_NO);
    let crc16 = bench_bundle_create(RUNS, crc::CRC_16);
    let crc32 = bench_bundle_create(RUNS, crc::CRC_32);

    //print!("{:x?}", crcno[0]);
    //println!("{}", bp7::hexify(&crcno[0]));

    bench_bundle_encode(RUNS, crc::CRC_NO);
    bench_bundle_encode(RUNS, crc::CRC_16);
    bench_bundle_encode(RUNS, crc::CRC_32);

    bench_bundle_load(RUNS, crc::CRC_NO, crcno);
    bench_bundle_load(RUNS, crc::CRC_16, crc16);
    bench_bundle_load(RUNS, crc::CRC_32, crc32);

    //dbg!(crcno[0].len());
    //dbg!(crc16[0].len());
    //dbg!(crc32[0].len());
}
