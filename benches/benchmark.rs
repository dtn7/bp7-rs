#[macro_use]
extern crate criterion;

use criterion::black_box;
use criterion::Criterion;
use std::convert::TryFrom;

use bp7::{bundle, canonical, crc, dtntime, eid, primary, Bundle, ByteBuffer};

fn bench_bundle_create(crc_type: crc::CrcRawType) -> ByteBuffer {
    let dst = eid::EndpointID::with_dtn("node2/inbox");
    let src = eid::EndpointID::with_dtn("node1/123456");
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);
    //let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);;

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(60 * 60 * 1_000_000)
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
    let mut b = bundle::Bundle::new(pblock, cblocks);

    b.set_crc(crc_type);
    b.validation_errors();
    b.to_cbor()
}

fn criterion_benchmark_bundle_create(c: &mut Criterion) {
    c.bench_function("create bundle no crc", |b| {
        b.iter(|| bench_bundle_create(crc::CRC_NO))
    });

    c.bench_function("create bundle crc 16", |b| {
        b.iter(|| bench_bundle_create(crc::CRC_16))
    });

    c.bench_function("create bundle crc 32", |b| {
        b.iter(|| bench_bundle_create(crc::CRC_32))
    });
}
fn criterion_benchmark_bundle_encode(c: &mut Criterion) {
    let dst = eid::EndpointID::with_dtn("node2/inbox");
    let src = eid::EndpointID::with_dtn("node1/123456");
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);
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
                1, // block number
                0, // flags
                0, // time elapsed
            ),
        ])
        .build()
        .unwrap();
    b.set_crc(crc::CRC_NO);
    b.validation_errors();
    let mut bndl = b.clone();
    c.bench_function("encode bundle no crc", move |bench| {
        bench.iter(|| bndl.to_cbor())
    });

    b.set_crc(crc::CRC_16);
    b.validation_errors();
    let mut bndl = b.clone();
    c.bench_function("encode bundle crc 16", move |bench| {
        bench.iter(|| bndl.to_cbor())
    });

    b.set_crc(crc::CRC_32);
    b.validation_errors();
    let mut bndl = b.clone();
    c.bench_function("encode bundle crc 32", move |bench| {
        bench.iter(|| bndl.to_cbor())
    });
}

fn criterion_benchmark_bundle_decode(c: &mut Criterion) {
    let b_no = bench_bundle_create(crc::CRC_NO);

    c.bench_function("decode bundle no crc", move |b| {
        b.iter(|| {
            let _deserialized: Bundle = Bundle::try_from(b_no.clone()).unwrap();
            _deserialized.validation_errors();
        })
    });

    let b_16 = bench_bundle_create(crc::CRC_16);

    c.bench_function("decode bundle crc 16", move |b| {
        b.iter(|| {
            let _deserialized: Bundle = Bundle::try_from(b_16.clone()).unwrap();
            _deserialized.validation_errors();
        })
    });

    let b_32 = bench_bundle_create(crc::CRC_32);

    c.bench_function("decode bundle crc 32", move |b| {
        b.iter(|| {
            let _deserialized: Bundle = Bundle::try_from(b_32.clone()).unwrap();
            _deserialized.validation_errors();
        })
    });
}
criterion_group!(
    benches,
    criterion_benchmark_bundle_create,
    criterion_benchmark_bundle_encode,
    criterion_benchmark_bundle_decode
);
criterion_main!(benches);
