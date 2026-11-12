use bp7::flags::*;

#[test]
fn block_control_flags_reserved_tests() {
    // unrecognized flags are ignored (RFC 9171 4.2.4)
    for flags in [
        0x00u8, 0x01, 0x02, 0x04, 0x10, 0x17, 0x80, 0x08, 0x20, 0x40, 0x68, 0x19, 0xf9, 0xff,
    ] {
        assert!(BlockValidation::validate(&flags).is_ok(), "{:#x}", flags);
    }
}

#[test]
fn bundle_control_flags_reserved_tests() {
    let defined = BundleControlFlags::BUNDLE_IS_FRAGMENT
        | BundleControlFlags::BUNDLE_MUST_NOT_FRAGMENTED
        | BundleControlFlags::BUNDLE_REQUEST_USER_APPLICATION_ACK
        | BundleControlFlags::BUNDLE_REQUEST_STATUS_TIME
        | BundleControlFlags::BUNDLE_STATUS_REQUEST_RECEPTION
        | BundleControlFlags::BUNDLE_STATUS_REQUEST_FORWARD
        | BundleControlFlags::BUNDLE_STATUS_REQUEST_DELIVERY
        | BundleControlFlags::BUNDLE_STATUS_REQUEST_DELETION;
    // unrecognized flags are ignored (RFC 9171 4.2.3)
    for flags in [0u64, defined.bits(), 1 << 21, 1 << 63] {
        assert!(BundleValidation::validate(&flags).is_ok(), "{:#x}", flags);
    }
    for bit in [3, 4, 7, 8, 9, 10, 11, 12, 13, 15, 19, 20] {
        let flags: u64 = 1 << bit;
        assert!(BundleValidation::validate(&flags).is_ok(), "bit {}", bit);
        let flags = flags | defined.bits();
        assert!(BundleValidation::validate(&flags).is_ok(), "bit {}", bit);
    }
}
