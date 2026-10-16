use bp7::crc::CRC_16;
use bp7::helpers::unhexify;
use bp7::{Bundle, primary};
use std::time::Duration;

#[test]
fn test_lifetime() {
    let p1 = primary::new_primary_block(
        "dtn://node1/",
        "dtn://node2/",
        bp7::dtntime::CreationTimestamp::now(),
        Duration::from_secs(10),
    );
    assert!(!p1.is_lifetime_exceeded());

    let p2 = primary::new_primary_block(
        "dtn://node1/",
        "dtn://node2/",
        bp7::dtntime::CreationTimestamp::with_time_and_seq(0, 0),
        Duration::from_secs(10),
    );
    assert!(!p2.is_lifetime_exceeded());

    let p2 = primary::new_primary_block(
        "dtn://node1/",
        "dtn://node2/",
        bp7::dtntime::CreationTimestamp::with_time_and_seq(1, 0),
        Duration::from_secs(10),
    );
    assert!(p2.is_lifetime_exceeded());

    // a maximal lifetime must not overflow
    let p3 = primary::new_primary_block(
        "dtn://node1/",
        "dtn://node2/",
        bp7::dtntime::CreationTimestamp::now(),
        Duration::from_millis(u64::MAX),
    );
    assert!(!p3.is_lifetime_exceeded());
}

#[test]
fn test_ipn_accept() {
    let hex_bundle = "9f88070000820282020182028201018202820001821b00ff00bb0e20b4ea001a000927c08507020100410085010100004d48656c6f2c20576f726c642142ff";
    let bytes = unhexify(hex_bundle);

    let mut bundle = Bundle::try_from(bytes.clone().unwrap().as_slice()).expect("CBOR decode");
    bundle.set_crc(CRC_16);
    bundle.calculate_crc();
    assert!(
        bundle.validate().is_ok(),
        "ipn:0.<nonzero> should get accepted and treated as ipn:0.0"
    );
}

#[test]
fn test_fragment_fields_decoding() {
    use bp7::crc::{CRC_NO, CrcBlock};
    use bp7::flags::BundleControlFlags;
    use bp7::primary::PrimaryBlock;

    for crc_type in [CRC_NO, CRC_16] {
        let mut p = primary::new_primary_block(
            "dtn://node1/",
            "dtn://node2/",
            bp7::dtntime::CreationTimestamp::with_time_and_seq(23, 42),
            Duration::from_secs(10),
        );
        p.bundle_control_flags = BundleControlFlags::BUNDLE_IS_FRAGMENT.bits();
        p.fragmentation_offset = 100;
        p.total_data_length = 1000;
        p.set_crc_type(crc_type);
        p.update_crc();

        let definite = serde_cbor::to_vec(&p).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<PrimaryBlock>(&definite).unwrap(),
            p
        );

        // same block as indefinite-length array
        let mut indefinite = definite.clone();
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        assert_eq!(
            serde_cbor::from_slice::<PrimaryBlock>(&indefinite).unwrap(),
            p
        );

        // fragment fields without fragment flag are rejected
        let mut no_flag = definite.clone();
        no_flag[2] = 0x00; // bundle control flags
        assert!(serde_cbor::from_slice::<PrimaryBlock>(&no_flag).is_err());
    }
}
