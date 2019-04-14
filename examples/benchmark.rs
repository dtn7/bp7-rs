use bp7::{bundle, canonical, crc, dtntime, eid, primary, Bundle, ByteBuffer};
use std::io::stdout;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const RUNS: i64 = 100_000;

fn bench_bundle_create(runs: i64, crc_type: crc::CRCType) -> Vec<ByteBuffer> {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    let mut bundles: Vec<ByteBuffer> = Vec::new();
    //let mut bundles: Vec<String> = Vec::new();

    print!("Creating {} bundles with {}: \t", RUNS, crc_str);
    stdout().flush().unwrap();

    use std::time::Instant;
    let bench_now = Instant::now();

    for _x in 0..runs {
        let dst = eid::EndpointID::with_dtn("node2/inbox".to_string());
        let src = eid::EndpointID::with_dtn("node1/123456".to_string());
        let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);;
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
                canonical::new_bundle_age_block(
                    1,
                    0,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis() as u64,
                ),
            ])
            .build()
            .unwrap();
        b.set_crc(crc_type);
        b.validation_errors();
        let _serialized = b.to_cbor();
        //let _serialized = b.to_json();
        bundles.push(_serialized);
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{} bundles/second", (runs as f64 / sec) as i64);
    bundles
}

fn bench_bundle_load(runs: i64, crc_type: crc::CRCType, mut bundles: Vec<ByteBuffer>) {
    let crc_str = match crc_type {
        crc::CRC_NO => "CRC_NO",
        crc::CRC_16 => "CRC_16",
        crc::CRC_32 => "CRC_32",
        _ => panic!("CRC_unknown"),
    };
    print!("Loading {} bundles with {}: \t", RUNS, crc_str);
    stdout().flush().unwrap();

    use std::time::Instant;
    let bench_now = Instant::now();

    for _x in 0..runs {
        let b = bundles.pop().unwrap();
        let _deserialized: Bundle = Bundle::from(b);
        _deserialized.validation_errors();
    }
    let elapsed = bench_now.elapsed();
    let sec = (elapsed.as_secs() as f64) + (f64::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
    println!("{} bundles/second", (runs as f64 / sec) as i64);
}
fn main() {
    let crcno = bench_bundle_create(RUNS, crc::CRC_NO);
    let crc16 = bench_bundle_create(RUNS, crc::CRC_16);
    let crc32 = bench_bundle_create(RUNS, crc::CRC_32);
    //print!("{:x?}", crcno[0]);

    bench_bundle_load(RUNS, crc::CRC_NO, crcno);
    bench_bundle_load(RUNS, crc::CRC_16, crc16);
    bench_bundle_load(RUNS, crc::CRC_32, crc32);
}
