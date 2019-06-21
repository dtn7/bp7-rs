use bp7::*;
use bp7::crc::CrcBlock;
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
    b.primary.set_crc(crc::CrcValue::Crc16([23,42]));
    assert!(b.crc_valid()== false);

    b.set_crc(crc::CRC_32);
    b.calculate_crc();
    b.primary.set_crc(crc::CrcValue::Crc32([23,42,23,42]));
    assert!(b.crc_valid() == false);
}