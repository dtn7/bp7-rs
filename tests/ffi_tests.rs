use bp7::ffi::*;
use bp7::*;
use std::ffi::CString;

#[test]
fn ffi_invalid_cbor_test() {
    unsafe {
        // [0x42, 0x43, 0x44, 0x45] is not a valid bundle
        let buf = bp7_buffer_test();
        assert!(bundle_from_cbor(buf).is_null());
        buffer_free(buf);
    }
}

#[test]
// random bundles have no crc, which is invalid with bpsec
#[cfg(not(feature = "bpsec"))]
fn ffi_roundtrip_test() {
    unsafe {
        let buf = helper_rnd_bundle();
        let bndl = bundle_from_cbor(buf);
        assert!(!bndl.is_null());
        assert!(bundle_is_valid(bndl));

        let meta = bundle_get_metadata(bndl);
        assert!(!meta.is_null());
        bundle_metadata_free(meta);

        let payload = bundle_payload(bndl);
        buffer_free(payload);

        let cbor = bundle_to_cbor(bndl);
        buffer_free(cbor);

        bundle_free(bndl);
        buffer_free(buf);
    }
}

#[test]
fn ffi_new_default_invalid_eid_test() {
    let valid = CString::new("dtn://node1/").unwrap();
    let invalid = CString::new("node1").unwrap();
    let none = CString::new("dtn:none").unwrap();
    unsafe {
        let payload = bp7_buffer_test();

        let bndl = bundle_new_default(valid.as_ptr(), valid.as_ptr(), 1000, payload);
        assert!(!bndl.is_null());
        bundle_free(bndl);

        assert!(bundle_new_default(invalid.as_ptr(), valid.as_ptr(), 1000, payload).is_null());
        assert!(bundle_new_default(valid.as_ptr(), invalid.as_ptr(), 1000, payload).is_null());
        assert!(bundle_new_default(valid.as_ptr(), none.as_ptr(), 1000, payload).is_null());

        buffer_free(payload);
    }
}

#[test]
fn ffi_metadata_nul_eid_test() {
    let mut b = bundle::new_std_payload_bundle(
        EndpointID::with_dtn("//no\0de/").unwrap(),
        "dtn://node2/".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    unsafe {
        assert!(bundle_get_metadata(&mut b).is_null());
    }
}
