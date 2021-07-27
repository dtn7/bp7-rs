use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    os::raw::c_char,
};

use crate::{
    bundle::BUNDLE_MUST_NOT_FRAGMENTED, helpers, new_payload_block, Bundle, CreationTimestamp,
    EndpointID,
};

#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: usize,
}

#[repr(C)]
pub struct BundleMetaData {
    src: *mut c_char,
    dst: *mut c_char,
    timestamp: u64,
    seqno: u64,
    lifetime: u64,
}

#[no_mangle]
pub extern "C" fn helper_rnd_bundle() -> Buffer {
    let mut bndl = helpers::rnd_bundle(CreationTimestamp::now());

    let mut buf = bndl.to_cbor().into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len();
    std::mem::forget(buf);
    Buffer { data, len }
}

#[no_mangle]
pub extern "C" fn buffer_free(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}

#[no_mangle]
pub extern "C" fn bundle_from_cbor(buf: Buffer) -> *mut Bundle {
    let buffer = unsafe {
        assert!(!buf.data.is_null());
        core::slice::from_raw_parts(buf.data, buf.len as usize)
    };
    let bndl: Bundle = buffer.to_owned().try_into().unwrap();
    //if bndl.validate().is_ok() {
    Box::into_raw(Box::new(bndl))
    //} else {
    //std::ptr::null()
    //}
}

#[no_mangle]
pub extern "C" fn bundle_to_cbor(bndl: *mut Bundle) -> Buffer {
    let bndl = unsafe {
        assert!(!bndl.is_null());
        &mut *bndl
    };
    let mut buf = bndl.to_cbor().into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len();
    std::mem::forget(buf);
    Buffer { data, len }
}

#[no_mangle]
pub extern "C" fn bundle_new_default(
    src: *const c_char,
    dst: *const c_char,
    lifetime: u64,
    payload: Buffer,
) -> *mut Bundle {
    let c_str_src = unsafe {
        assert!(!src.is_null());

        CStr::from_ptr(src)
    };

    let r_src = c_str_src.to_str().unwrap();
    let src_eid: EndpointID = r_src.try_into().unwrap();

    let c_str_dst = unsafe {
        assert!(!dst.is_null());

        CStr::from_ptr(dst)
    };
    let r_dst = c_str_dst.to_str().unwrap();
    let dst_eid: EndpointID = r_dst.try_into().unwrap();

    let data = unsafe {
        assert!(!payload.data.is_null());
        core::slice::from_raw_parts(payload.data, payload.len as usize)
    };

    let pblock = crate::primary::PrimaryBlockBuilder::default()
        .bundle_control_flags(BUNDLE_MUST_NOT_FRAGMENTED)
        .destination(dst_eid)
        .source(src_eid.clone())
        .report_to(src_eid)
        .creation_timestamp(CreationTimestamp::now())
        .lifetime(core::time::Duration::from_millis(lifetime))
        .build()
        .unwrap();
    let mut b = crate::bundle::Bundle::new(pblock, vec![new_payload_block(0, data.to_owned())]);
    b.set_crc(crate::crc::CRC_NO);
    b.sort_canonicals();
    Box::into_raw(Box::new(b))
}

#[no_mangle]
pub extern "C" fn bundle_free(ptr: *mut Bundle) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn bundle_get_metadata(bndl: *mut Bundle) -> BundleMetaData {
    let bndl = unsafe {
        assert!(!bndl.is_null());
        &mut *bndl
    };
    let timestamp = bndl.primary.creation_timestamp.dtntime();
    let seqno = bndl.primary.creation_timestamp.seqno();
    let lifetime = bndl.primary.lifetime.as_millis() as u64;
    let src_str = CString::new(bndl.primary.source.to_string()).unwrap();
    let src = src_str.into_raw();
    let dst_str = CString::new(bndl.primary.destination.to_string()).unwrap();
    let dst = dst_str.into_raw();
    BundleMetaData {
        src,
        dst,
        timestamp,
        seqno,
        lifetime,
    }
}

#[no_mangle]
pub extern "C" fn bundle_metadata_free(meta: BundleMetaData) {
    if !meta.src.is_null() {
        unsafe {
            CString::from_raw(meta.src);
        }
    }

    if !meta.dst.is_null() {
        unsafe {
            CString::from_raw(meta.dst);
        }
    }
}

#[no_mangle]
pub extern "C" fn bundle_is_valid(bndl: *mut Bundle) -> bool {
    let bndl = unsafe {
        assert!(!bndl.is_null());
        &mut *bndl
    };
    bndl.validate().is_ok()
}

#[no_mangle]
pub extern "C" fn bundle_payload(bndl: *mut Bundle) -> Buffer {
    if !bndl.is_null() {
        let bndl = unsafe { &mut *bndl };
        if let Some(payload) = bndl.payload() {
            let mut buf = payload.clone().into_boxed_slice();
            let data = buf.as_mut_ptr();
            let len = buf.len();
            std::mem::forget(buf);
            return Buffer { data, len };
        }
    }
    Buffer {
        data: std::ptr::null_mut(),
        len: 0,
    }
}
