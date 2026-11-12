//! Bundles reported by interoperability tests of other implementations

use bp7::helpers::unhexify;
use bp7::*;
use std::convert::TryFrom;

/// Unrecognized block processing control flags are ignored (RFC 9171 4.2.4), issue #12
#[test]
fn reserved_block_flags_are_accepted_and_kept() {
    let hex = "9f89071844018202820301820100820100821b000000b5998c982b011a000493e042c9f68506021000458202820200850704010042183485010118f9004454455354ff";
    let mut bundle = Bundle::try_from(unhexify(hex).unwrap().as_slice()).unwrap();
    assert!(bundle.validate().is_ok(), "{:?}", bundle.validate());
    let payload = bundle
        .extension_block_by_type(canonical::PAYLOAD_BLOCK)
        .unwrap();
    assert_eq!(payload.block_control_flags, 0xf9);
    // forwarded unchanged
    assert_eq!(bundle.to_cbor(), unhexify(hex).unwrap());
}

/// Block-type-specific data and CRCs are CBOR byte strings (RFC 9171 4.3.2), issue #20
#[test]
fn text_strings_as_block_data_are_rejected() {
    // payload block data of the issue as text string
    let text = "9f88070000820282020182028201018202820100821b000000bb0e20b4ea001a000927c08507020100410086010100016d48656c6c6f2c20576f726c64214254b3ff";
    let err = Bundle::try_from(unhexify(text).unwrap().as_slice()).unwrap_err();
    assert!(err.to_string().contains("byte string"), "{}", err);

    // the same bundle with a byte string is accepted
    let bytes = text.replace(
        "016d48656c6c6f2c20576f726c6421",
        "014d48656c6c6f2c20576f726c6421",
    );
    let bundle = Bundle::try_from(unhexify(&bytes).unwrap().as_slice()).unwrap();
    assert_eq!(bundle.payload().unwrap(), &b"Hello, World!".to_vec());
}
