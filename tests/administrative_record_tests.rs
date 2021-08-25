use bp7::administrative_record::*;
use bp7::flags::*;
use bp7::*;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

fn new_complete_bundle(crc_type: bp7::crc::CrcRawType) -> Bundle {
    let dst = eid::EndpointID::try_from("dtn://node2/inbox").unwrap();
    let src = eid::EndpointID::try_from("dtn://node1/123456").unwrap();
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

#[test]
fn status_report_tests() {
    use bp7::flags::*;
    let mut bndl = new_complete_bundle(crc::CRC_NO);
    let mut flags = bndl.primary.bundle_control_flags.flags();
    flags |= bp7::flags::BundleControlFlags::BUNDLE_STATUS_REQUEST_DELETION;
    bndl.primary.bundle_control_flags = flags.bits();
    assert!(!bndl.is_administrative_record());

    let sr1 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED,));

    let expected_refbundle = format!(
        "dtn://node1/123456-{}-0",
        bndl.primary.creation_timestamp.dtntime()
    );
    assert_eq!(sr1.refbundle(), expected_refbundle);

    let encoded_sr1 = serde_cbor::to_vec(&sr1).unwrap();

    let sr1_dec: StatusReport = serde_cbor::from_slice(&encoded_sr1).unwrap();

    assert_eq!(sr1, sr1_dec);

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    let mut flags = bndl.primary.bundle_control_flags.flags();
    flags |= BundleControlFlags::BUNDLE_STATUS_REQUEST_DELETION;
    flags |= BundleControlFlags::BUNDLE_REQUEST_STATUS_TIME;
    bndl.primary.bundle_control_flags = flags.bits();

    let sr2 = dbg!(new_status_report(&bndl, DELETED_BUNDLE, LIFETIME_EXPIRED));

    let encoded_sr2 = serde_cbor::to_vec(&sr2).unwrap();

    let sr2_dec: StatusReport = serde_cbor::from_slice(&encoded_sr2).unwrap();

    assert_eq!(sr2, sr2_dec);

    let mut bndl = new_complete_bundle(crc::CRC_NO);
    bndl.primary.bundle_control_flags =
        BundleControlFlags::BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD.bits();
    assert!(bndl.is_administrative_record()); // actually not true since no payload block has been added
}
