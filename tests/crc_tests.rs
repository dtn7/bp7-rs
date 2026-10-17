use bp7::bundle::Block;
use bp7::crc::CrcBlock;
use bp7::*;
#[test]
fn crc_valid_tests() {
    let mut b = helpers::rnd_bundle(dtntime::CreationTimestamp::now());
    b.set_crc(crc::CRC_NO);
    b.calculate_crc();
    assert!(b.crc_valid());

    b.set_crc(crc::CRC_16);
    b.calculate_crc();
    assert!(b.crc_valid());

    b.set_crc(crc::CRC_32);
    b.calculate_crc();
    assert!(b.crc_valid());
}

#[test]
fn crc_invalid_tests() {
    let mut b = helpers::rnd_bundle(dtntime::CreationTimestamp::now());

    b.set_crc(crc::CRC_16);
    b.calculate_crc();
    b.primary.set_crc(crc::CrcValue::Crc16([23, 42]));
    assert!(!b.crc_valid());

    b.set_crc(crc::CRC_32);
    b.calculate_crc();
    b.primary.set_crc(crc::CrcValue::Crc32([23, 42, 23, 42]));
    assert!(!b.crc_valid());
}

#[test]
fn crc_unknown_type_tests() {
    let mut b = helpers::rnd_bundle(dtntime::CreationTimestamp::now());
    b.set_crc(crc::CRC_NO);
    let mut bytes = b.to_cbor();
    // patch crc type of payload block header [1, 1, 0, 0, ...] from 0 to 3
    let pos = bytes
        .windows(5)
        .position(|w| w == [0x85, 0x01, 0x01, 0x00, 0x00])
        .unwrap();
    bytes[pos + 4] = 0x03;

    let mut b2 = Bundle::try_from(bytes.as_slice()).unwrap();
    assert_eq!(
        b2.extension_block_by_type(PAYLOAD_BLOCK).unwrap().crc,
        crc::CrcValue::Unknown(3)
    );
    assert!(b2.validate().is_err());
    assert!(!b2.crc_valid());

    // re-encoding must not fail and must produce a decodable bundle
    let reencoded = b2.to_cbor();
    assert_eq!(reencoded, bytes);
    assert!(Bundle::try_from(reencoded.as_slice()).is_ok());
}

#[test]
fn crc_streaming_matches_encoding_tests() {
    // crc over the encoding with an empty crc value, as calculated before streaming
    fn expected<T: crc::CrcBlock + bundle::Block>(blck: &T) -> crc::CrcValue {
        let mut empty = blck.clone();
        empty.reset_crc();
        let data = empty.to_cbor();
        match blck.crc_type() {
            crc::CRC_16 => crc::CrcValue::Crc16(crc::X25.checksum(&data).to_be_bytes()),
            _ => crc::CrcValue::Crc32(crc::CASTAGNOLI.checksum(&data).to_be_bytes()),
        }
    }

    for crc_type in [crc::CRC_16, crc::CRC_32] {
        let mut b = helpers::rnd_bundle(dtntime::CreationTimestamp::now());
        b.set_payload(vec![0x42; 100_000]);
        b.set_crc(crc_type);
        b.calculate_crc();
        assert_eq!(b.primary.crc, expected(&b.primary));
        for c in &b.canonicals {
            assert_eq!(c.crc, expected(c));
            assert!(c.check_crc());
        }
        assert!(b.primary.check_crc());
        assert!(b.validate().is_ok());
    }
}

#[test]
fn crc_single_pass_encoding_tests() {
    for crc_type in [crc::CRC_NO, crc::CRC_16, crc::CRC_32] {
        let mut b = helpers::rnd_bundle(dtntime::CreationTimestamp::now());
        b.set_payload(vec![0x42; 10_000]);
        b.set_crc(crc_type);
        // stale crc values must be replaced
        if crc_type == crc::CRC_32 {
            b.primary.set_crc(crc::CrcValue::Crc32([1, 2, 3, 4]));
        }
        let cbor = b.to_cbor();

        // same encoding as calculating the crcs first and encoding afterwards
        let mut expected = b.clone();
        expected.calculate_crc();
        let mut expected_cbor = vec![0x9f];
        expected_cbor.extend(expected.primary.to_cbor());
        for c in &expected.canonicals {
            expected_cbor.extend(c.to_cbor());
        }
        expected_cbor.push(0xff);
        assert_eq!(cbor, expected_cbor);
        // crc values are updated in the bundle
        assert_eq!(b, expected);

        let mut decoded = Bundle::try_from(cbor.as_slice()).unwrap();
        assert!(decoded.crc_valid());
    }
}
