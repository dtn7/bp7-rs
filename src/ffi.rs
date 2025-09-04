use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    os::raw::c_char,
};

use crate::{
    Bundle, CreationTimestamp, EndpointID, flags::BlockControlFlags, flags::BundleControlFlags,
    helpers, new_payload_block, primary,
};

#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: u32,
}

#[repr(C)]
pub struct BundleMetaData {
    /// The source EndpointID
    src: *mut c_char,
    /// The destination EndpointID
    dst: *mut c_char,
    /// The creation timestamp in DTN time
    timestamp: u64,
    /// The sequence number
    seqno: u64,
    /// The lifetime of a bundle in ms
    lifetime: u64,
}

/// A simple test for the bp7 FFI interface.
/// On success it should always return the number 23.
#[unsafe(no_mangle)]
pub extern "C" fn bp7_working() -> u8 {
    23
}

/// Another simple test returning a dynamic buffer with a fixed content.
/// The returned buffer contains the following bytes: [0x42, 0x43, 0x44, 0x45]
#[unsafe(no_mangle)]
pub extern "C" fn bp7_buffer_test() -> *mut Buffer {
    let input = vec![0x42, 0x43, 0x44, 0x45];

    let mut buf = input.into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len() as u32;
    std::mem::forget(buf);
    Box::into_raw(Box::new(Buffer { data, len }))
}

/// Generate a random bundle as a raw buffer.
#[unsafe(no_mangle)]
pub extern "C" fn helper_rnd_bundle() -> *mut Buffer {
    let mut bndl = helpers::rnd_bundle(CreationTimestamp::now());

    let mut buf = bndl.to_cbor().into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len() as u32;
    std::mem::forget(buf);
    Box::into_raw(Box::new(Buffer { data, len }))
}

/// Free the memory of a given buffer.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn buffer_free(buf: *mut Buffer) {
    unsafe {
        if buf.is_null() {
            return;
        }
        drop(Box::from_raw(buf));
    }
}

/// Try to decode a bundle from a given buffer.
///
/// In case of failure, a null pointer is returned instead of a bundle.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_from_cbor(ptr: *mut Buffer) -> *mut Bundle {
    unsafe {
        assert!(!ptr.is_null());
        let buf = &mut *ptr;
        //println!("buf len {}", buf.len);
        assert!(!buf.data.is_null());
        let buffer = core::slice::from_raw_parts(buf.data, buf.len as usize);
        //println!("buffer {}", helpers::hexify(buffer));
        let bndl: Bundle = buffer
            .to_owned()
            .try_into()
            .expect("failed to load bundle from buffer");
        if bndl.validate().is_ok() {
            Box::into_raw(Box::new(bndl))
        } else {
            std::ptr::null_mut::<Bundle>()
        }
    }
}

/// Encode a given bundle a CBOR byte buffer
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_to_cbor(bndl: *mut Bundle) -> *mut Buffer {
    unsafe {
        assert!(!bndl.is_null());
        let bndl = &mut *bndl;
        let mut buf = bndl.to_cbor().into_boxed_slice();
        let data = buf.as_mut_ptr();
        let len = buf.len() as u32;
        std::mem::forget(buf);
        Box::into_raw(Box::new(Buffer { data, len }))
    }
}

/// Create a new bundle with standard configuration and a given payload
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_new_default(
    src: *const c_char,
    dst: *const c_char,
    lifetime: u64,
    ptr: *mut Buffer,
) -> *mut Bundle {
    unsafe {
        assert!(!src.is_null());
        let c_str_src = CStr::from_ptr(src);

        let r_src = c_str_src.to_str().unwrap();
        let src_eid: EndpointID = r_src.try_into().unwrap();

        assert!(!dst.is_null());
        let c_str_dst = CStr::from_ptr(dst);
        let r_dst = c_str_dst.to_str().unwrap();
        let dst_eid: EndpointID = r_dst.try_into().unwrap();

        assert!(!ptr.is_null());
        let payload = &mut *ptr;
        assert!(!payload.data.is_null());
        let data = core::slice::from_raw_parts(payload.data, payload.len as usize);

        let pblock = primary::PrimaryBlockBuilder::default()
            .bundle_control_flags(BundleControlFlags::BUNDLE_MUST_NOT_FRAGMENTED.bits())
            .destination(dst_eid)
            .source(src_eid.clone())
            .report_to(src_eid)
            .creation_timestamp(CreationTimestamp::now())
            .lifetime(core::time::Duration::from_millis(lifetime))
            .build()
            .unwrap();
        let mut b = Bundle::new(
            pblock,
            vec![new_payload_block(
                BlockControlFlags::empty(),
                data.to_owned(),
            )],
        );
        b.set_crc(crate::crc::CRC_NO);
        b.sort_canonicals();
        Box::into_raw(Box::new(b))
    }
}

/// Frees the memory of a given bundle.
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_free(ptr: *mut Bundle) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        drop(Box::from_raw(ptr));
    }
}

/// Get the metadata from a given bundle.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_get_metadata(bndl: *mut Bundle) -> *mut BundleMetaData {
    unsafe {
        assert!(!bndl.is_null());
        let bndl = &mut *bndl;
        let timestamp = bndl.primary.creation_timestamp.dtntime();
        let seqno = bndl.primary.creation_timestamp.seqno();
        let lifetime = bndl.primary.lifetime.as_millis() as u64;
        let src_str = CString::new(bndl.primary.source.to_string()).unwrap();
        let src = src_str.into_raw();
        let dst_str = CString::new(bndl.primary.destination.to_string()).unwrap();
        let dst = dst_str.into_raw();
        Box::into_raw(Box::new(BundleMetaData {
            src,
            dst,
            timestamp,
            seqno,
            lifetime,
        }))
    }
}

/// Frees a BundleMetaData struct.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_metadata_free(ptr: *mut BundleMetaData) {
    unsafe {
        assert!(!ptr.is_null());
        let meta = &mut *ptr;
        if !meta.src.is_null() {
            drop(CString::from_raw(meta.src));
        }

        if !meta.dst.is_null() {
            drop(CString::from_raw(meta.dst));
        }
    }
}

/// Check if a given bundle is valid.
/// This checks the primary block as well as the validity of all canonical bundles.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_is_valid(bndl: *mut Bundle) -> bool {
    unsafe {
        assert!(!bndl.is_null());
        let bndl = &mut *bndl;
        bndl.validate().is_ok()
    }
}

/// Get the payload of a given bundle.
///
/// # Safety
///
/// Should only be called from FFI interface.
/// This function can lead to UB as pointer cannot be validated!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bundle_payload(bndl: *mut Bundle) -> *mut Buffer {
    unsafe {
        if !bndl.is_null() {
            let bndl = &mut *bndl;
            if let Some(payload) = bndl.payload() {
                let mut buf = payload.clone().into_boxed_slice();
                let data = buf.as_mut_ptr();
                let len = buf.len() as u32;
                std::mem::forget(buf);
                return Box::into_raw(Box::new(Buffer { data, len }));
            }
        }
        Box::into_raw(Box::new(Buffer {
            data: std::ptr::null_mut(),
            len: 0,
        }))
    }
}
