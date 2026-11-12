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
