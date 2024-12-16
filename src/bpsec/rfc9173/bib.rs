// SHA Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-sha-variant
pub type ShaVariantType = u16;
pub const HMAC_SHA_256: ShaVariantType = 5;
pub const HMAC_SHA_384: ShaVariantType = 6; // default
pub const HMAC_SHA_512: ShaVariantType = 7;
