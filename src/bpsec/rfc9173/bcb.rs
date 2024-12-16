// use aes_gcm::aead::{
//     generic_array::{typenum, GenericArray},
//     Aead, KeyInit, Payload,
// };
// use aes_gcm::aes::{Aes128, Aes256};
// use aes_gcm::AesGcm;

// use aes_kw::Kek;

// AES Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aes-gcm
pub type AesVariantType = u16;
pub const AES_128_GCM: AesVariantType = 1;
pub const AES_256_GCM: AesVariantType = 3; // default
