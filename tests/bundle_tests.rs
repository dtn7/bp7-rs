use bp7::flags::*;
use bp7::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::time::Duration;

fn new_complete_bundle(crc_type: bp7::crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox").unwrap();
    let src = eid::EndpointID::with_dtn("node1/123456").unwrap();
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(Duration::from_secs(60 * 60))
        .build()
        .unwrap();

    let mut b = bundle::BundleBuilder::default()
        .primary(pblock)
        .canonicals(vec![
            canonical::new_payload_block(BlockControlFlags::empty(), b"ABC".to_vec()),
            canonical::new_bundle_age_block(
                2,                          // block number
                BlockControlFlags::empty(), // flags
                0,                          // time elapsed
            ),
            canonical::new_hop_count_block(
                3,                          // block number
                BlockControlFlags::empty(), // flags
                16,                         // max hops
            ),
            canonical::new_previous_node_block(
                4,                                  // block number
                BlockControlFlags::empty(),         // flags
                "dtn://node23".try_into().unwrap(), // previous node EID
            ),
        ])
        .build()
        .unwrap();
    b.set_crc(crc_type);
    b.calculate_crc();
    assert!(b.validate().is_ok());
    b
}

fn new_empty_bundle(crc_type: bp7::crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox").unwrap();
    let src = eid::EndpointID::with_dtn("node1/123456").unwrap();
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(Duration::from_secs(60 * 60))
        .build()
        .unwrap();

    let mut b = bundle::BundleBuilder::default()
        .primary(pblock)
        .canonicals(vec![])
        .build()
        .unwrap();
    b.set_crc(crc_type);
    b.calculate_crc();
    assert!(b.validate().is_ok());
    b
}
fn new_complete_bundle_invalid(crc_type: bp7::crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox").unwrap();
    let src = eid::EndpointID::with_dtn("node1/123456").unwrap();
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(Duration::from_secs(60 * 60))
        .build()
        .unwrap();

    let mut b = bundle::BundleBuilder::default()
        .primary(pblock)
        .canonicals(vec![
            canonical::new_payload_block(BlockControlFlags::empty(), b"ABC".to_vec()),
            canonical::new_bundle_age_block(
                2,                          // block number
                BlockControlFlags::empty(), // flags
                0,                          // time elapsed
            ),
            canonical::new_hop_count_block(
                2,                          // block number
                BlockControlFlags::empty(), // flags
                16,                         // max hops
            ),
            canonical::new_previous_node_block(
                2,                                  // block number
                BlockControlFlags::empty(),         // flags
                "dtn://node23".try_into().unwrap(), // previous node EID
            ),
        ])
        .build()
        .unwrap();
    b.set_crc(crc_type);
    b.calculate_crc();
    b
}

#[test]
fn bundle_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.try_into().unwrap();
    assert_eq!(bndl, decoded);

    let mut bndl = new_complete_bundle(crc::CRC_16);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.try_into().unwrap();
    assert_eq!(bndl, decoded);

    let mut bndl = new_complete_bundle(crc::CRC_32);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.try_into().unwrap();
    assert_eq!(bndl, decoded);
}

#[test]
fn bundle_helpers() {
    let bndl = new_complete_bundle(crc::CRC_NO);
    assert!(bndl.previous_node().is_some());

    let bndl = new_empty_bundle(crc::CRC_NO);
    assert!(bndl.previous_node().is_none());
}
#[test]
fn bundle_invalid_cbor() {
    let invalid_cbor_bytes = vec![0x41, 0x41];
    let maybe_bundle = Bundle::try_from(invalid_cbor_bytes);
    assert!(maybe_bundle.is_err());
}

#[test]
fn bundle_invalid_cblock_numbers_tests() {
    assert!(new_complete_bundle_invalid(crc::CRC_NO).validate().is_err());
    assert!(new_complete_bundle_invalid(crc::CRC_16).validate().is_err());
    assert!(new_complete_bundle_invalid(crc::CRC_32).validate().is_err());
}

#[test]
fn bundle_canonical_update_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    {
        let hcblock = bndl.extension_block_by_type_mut(HOP_COUNT_BLOCK).unwrap();
        assert!(hcblock.hop_count_increase());
    }
    let hcb2 = bndl.extension_block_by_type_mut(HOP_COUNT_BLOCK).unwrap();
    assert!(hcb2.hop_count_get().unwrap() == (16, 1));

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    assert!(bndl.update_extensions("dtn://newnode".try_into().unwrap(), 23));

    let cb = bndl.extension_block_by_type_mut(HOP_COUNT_BLOCK).unwrap();
    assert!(cb.hop_count_get().unwrap() == (16, 1));
    let cb = bndl.extension_block_by_type_mut(BUNDLE_AGE_BLOCK).unwrap();
    assert!(cb.bundle_age_get().unwrap() == 23);
    let cb = bndl
        .extension_block_by_type_mut(PREVIOUS_NODE_BLOCK)
        .unwrap();
    assert!(cb.previous_node_get().unwrap() == &EndpointID::try_from("dtn://newnode").unwrap());
}

#[test]
fn bundle_add_cblock() {
    let mut b = new_empty_bundle(crc::CRC_NO);
    assert!(b.canonicals.is_empty());

    b.add_canonical_block(canonical::new_hop_count_block(
        666,                        // block number
        BlockControlFlags::empty(), // flags
        16,                         // max hops
    ));
    assert!(b.canonicals.len() == 1);

    b.add_canonical_block(canonical::new_hop_count_block(
        666,                        // block number
        BlockControlFlags::empty(), // flags
        16,                         // max hops
    ));
    // Already present, should be ignored
    assert!(b.canonicals.len() == 1);

    b.add_canonical_block(canonical::new_payload_block(
        BlockControlFlags::empty(),
        b"ABC".to_vec(),
    ));
    assert!(b.canonicals.len() == 2);

    b.add_canonical_block(canonical::new_bundle_age_block(
        666,                        // block number
        BlockControlFlags::empty(), // flags
        0,                          // time elapsed
    ));
    assert!(b.canonicals.len() == 3);

    let numbers: Vec<u64> = b.canonicals.iter().map(|c| c.block_number).collect();
    //numbers.sort();
    assert_eq!(numbers, vec![3, 2, 1]);

    let mut b = new_complete_bundle(crc::CRC_NO);
    assert_eq!(b.payload().unwrap(), b"ABC");
    let pl = b
        .extension_block_by_type_mut(bp7::canonical::PAYLOAD_BLOCK)
        .unwrap();
    pl.set_data(bp7::canonical::CanonicalData::Data(b"XYZ".to_vec()));
    assert_eq!(b.payload().unwrap(), b"XYZ");

    b.set_payload("123".into());
    assert_eq!(b.payload().unwrap(), b"123");
}
