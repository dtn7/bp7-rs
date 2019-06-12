use bp7::*;

fn new_complete_bundle(crc_type: bp7::crc::CRCType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox".to_string());
    let src = eid::EndpointID::with_dtn("node1/123456".to_string());
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);

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
            canonical::new_hop_count_block(
                2,  // block number
                0,  // flags
                16, // max hops
            ),
            canonical::new_previous_node_block(
                3,                     // block number
                0,                     // flags
                "dtn://node23".into(), // previous node EID
            ),
        ])
        .build()
        .unwrap();
    b.set_crc(crc_type);
    b.calculate_crc();
    assert!(b.validation_errors().is_none());
    b
}
fn new_complete_bundle_invalid(crc_type: bp7::crc::CRCType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox".to_string());
    let src = eid::EndpointID::with_dtn("node1/123456".to_string());
    let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);

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
            canonical::new_hop_count_block(
                1,  // block number
                0,  // flags
                16, // max hops
            ),
            canonical::new_previous_node_block(
                1,                     // block number
                0,                     // flags
                "dtn://node23".into(), // previous node EID
            ),
        ])
        .build()
        .unwrap();
    b.set_crc(crc_type);
    b.calculate_crc();
    assert!(b.validation_errors().is_some());
    b
}
#[test]
fn bundle_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.into();
    assert_eq!(bndl, decoded);

    let mut bndl = new_complete_bundle(crc::CRC_16);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.into();
    assert_eq!(bndl, decoded);

    let mut bndl = new_complete_bundle(crc::CRC_32);
    let encoded = bndl.to_cbor();
    let decoded: Bundle = encoded.into();
    assert_eq!(bndl, decoded);
}

#[test]
fn bundle_invalid_cblock_numbers_tests() {
    new_complete_bundle_invalid(crc::CRC_NO);

    new_complete_bundle_invalid(crc::CRC_16);

    new_complete_bundle_invalid(crc::CRC_32);
}

#[test]
fn bundle_canonical_update_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    {
        let hcblock = bndl.extension_block(HOP_COUNT_BLOCK).unwrap();
        assert!(hcblock.hop_count_increase());
    }
    let hcb2 = bndl.extension_block(HOP_COUNT_BLOCK).unwrap();
    assert!(hcb2.hop_count_get().unwrap() == (16, 1));

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    assert!(bndl.update_extensions("dtn://newnode".into(), 23));

    let cb = bndl.extension_block(HOP_COUNT_BLOCK).unwrap();
    assert!(cb.hop_count_get().unwrap() == (16, 1));
    let cb = bndl.extension_block(BUNDLE_AGE_BLOCK).unwrap();
    assert!(cb.bundle_age_get().unwrap() == 23);
    let cb = bndl.extension_block(PREVIOUS_NODE_BLOCK).unwrap();
    assert!(cb.previous_node_get().unwrap() == &EndpointID::from("dtn://newnode"));
}