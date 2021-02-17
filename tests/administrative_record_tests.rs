use bp7::administrative_record::*;
use bp7::*;
use helpers::from_slice;
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
            canonical::new_payload_block(0, b"ABC".to_vec()),
            canonical::new_bundle_age_block(
                2, // block number
                0, // flags
                0, // time elapsed
            ),
            canonical::new_hop_count_block(
                3,  // block number
                0,  // flags
                16, // max hops
            ),
            canonical::new_previous_node_block(
                4,                                  // block number
                0,                                  // flags
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

#[test]
fn status_report_tests() {
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_STATUS_REQUEST_DELETION;
    assert!(!bndl.is_administrative_record());

    let sr1 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED,));

    let expected_refbundle = format!(
        "dtn://node1/123456-{}-0",
        bndl.primary.creation_timestamp.dtntime()
    );
    assert_eq!(sr1.refbundle(), expected_refbundle);

    let mut encoded_sr1 = Vec::new();
    ciborium::ser::into_writer(&sr1, &mut encoded_sr1).unwrap();

    let sr1_dec: StatusReport = from_slice(&encoded_sr1).unwrap();

    assert_eq!(sr1, sr1_dec);

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_STATUS_REQUEST_DELETION;
    bndl.primary.bundle_control_flags |= bp7::bundle::BUNDLE_REQUEST_STATUS_TIME;
    let sr2 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED));

    let mut encoded_sr2 = Vec::new();
    ciborium::ser::into_writer(&sr2, &mut encoded_sr2).unwrap();

    let sr2_dec: StatusReport = from_slice(&encoded_sr2).unwrap();

    assert_eq!(sr2, sr2_dec);

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags = bp7::bundle::BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD;
    assert!(bndl.is_administrative_record()); // actually not true since no payload block has been added
}
