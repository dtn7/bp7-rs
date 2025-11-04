use bp7::helpers::unhexify;
use bp7::{Bundle, primary};
use std::time::Duration;
use bp7::crc::CRC_16;

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
