//! Default security contexts for BPSec ([RFC 9173](https://www.rfc-editor.org/rfc/rfc9173.html))
//!
//! Both security contexts can carry the key of their security operation wrapped
//! with the AES key wrap function (RFC 3394) in their wrapped key parameter. If a
//! security block has a wrapped key, the key given to its security operations is
//! the key encryption key used to unwrap it, as the key of the operation MUST be
//! derived from the wrapped key in this case (RFC 9173 3.8.2, 4.8.2). Otherwise
//! the given key is used for the operation directly.

pub mod bcb;
pub mod bib;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;

use crate::bpsec::BpsecError;
use crate::bundle::ByteBuffer;

fn invalid_kek() -> BpsecError {
    BpsecError::InvalidKey("key encryption key must have 16, 24 or 32 bytes".to_string())
}

/// Wrap a key with the AES key wrap function (RFC 3394) for the wrapped key parameter.
///
/// The key encryption key must have 16, 24 or 32 bytes, the wrapped key a multiple of
/// 8 bytes and at least 16 bytes.
pub fn wrap_key(kek: &[u8], key: &[u8]) -> Result<ByteBuffer, BpsecError> {
    let wrapped = match kek.len() {
        16 => Kek::<Aes128>::new(GenericArray::from_slice(kek)).wrap_vec(key),
        24 => Kek::<Aes192>::new(GenericArray::from_slice(kek)).wrap_vec(key),
        32 => Kek::<Aes256>::new(GenericArray::from_slice(kek)).wrap_vec(key),
        _ => return Err(invalid_kek()),
    };
    wrapped.map_err(|_| {
        BpsecError::InvalidKey("keys to wrap must be multiples of 8 bytes".to_string())
    })
}

/// Unwrap a key of a wrapped key parameter with the AES key wrap function (RFC 3394)
pub fn unwrap_key(kek: &[u8], wrapped_key: &[u8]) -> Result<ByteBuffer, BpsecError> {
    let key = match kek.len() {
        16 => Kek::<Aes128>::new(GenericArray::from_slice(kek)).unwrap_vec(wrapped_key),
        24 => Kek::<Aes192>::new(GenericArray::from_slice(kek)).unwrap_vec(wrapped_key),
        32 => Kek::<Aes256>::new(GenericArray::from_slice(kek)).unwrap_vec(wrapped_key),
        _ => return Err(invalid_kek()),
    };
    // the integrity check of the key wrap fails for a wrong key encryption key
    key.map_err(|_| BpsecError::OperationFailed("unwrapping the wrapped key failed".to_string()))
}

/// Key of a security operation, unwrapped with the given key if a wrapped key is present
pub(crate) fn operation_key(
    key: &[u8],
    wrapped_key: Option<&[u8]>,
) -> Result<ByteBuffer, BpsecError> {
    match wrapped_key {
        Some(wrapped_key) => unwrap_key(key, wrapped_key),
        None => Ok(key.to_vec()),
    }
}
