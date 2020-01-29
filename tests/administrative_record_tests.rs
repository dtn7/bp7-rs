use bp7::*;
use bp7::administrative_record::*;

fn new_complete_bundle(crc_type : bp7::crc::CRCType) -> Bundle {
    let dst = eid::EndpointID::with_dtn("node2/inbox");
    let src = eid::EndpointID::with_dtn("node1/123456");
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
                2, // block number
                0, // flags
                0, // time elapsed
            ),
            canonical::new_hop_count_block(
                3, // block number
                0, // flags
                16, // max hops
            ),
            canonical::new_previous_node_block(
                4, // block number
                0, // flags
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

#[test]
fn status_report_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_STATUS_REQUEST_DELETION;

    let sr1 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED, dtn_time_now()));

    let encoded_sr1 = serde_cbor::to_vec(&sr1).unwrap();

    let sr1_dec : StatusReport = serde_cbor::from_slice(&encoded_sr1).unwrap();

    assert_eq!(sr1, sr1_dec);

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_STATUS_REQUEST_DELETION;
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_REQUEST_STATUS_TIME;
    let sr2 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED, dtn_time_now()));

    let encoded_sr2 = serde_cbor::to_vec(&sr2).unwrap();

    let sr2_dec : StatusReport = serde_cbor::from_slice(&encoded_sr2).unwrap();

    assert_eq!(sr2, sr2_dec);
}
