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
