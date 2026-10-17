//! BCB-AES-GCM security context ([RFC 9173 4](https://www.rfc-editor.org/rfc/rfc9173.html#name-security-context-bcb-aes-gc))
//!
//! Only the security context parameters and results are defined so far, the
//! encryption and decryption are not implemented yet.

use serde_cbor::Value;

use crate::bpsec::*;

// AES Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aes-gcm
pub type AesVariantType = u16;
pub const AES_128_GCM: AesVariantType = 1;
pub const AES_256_GCM: AesVariantType = 3; // default

// AAD Scope Flags
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aad-scope-flags
pub type AadScopeFlagsType = u16;

// Security context parameter ids (RFC 9173 4.3)
pub const IV_PARAMETER: u64 = 1;
pub const AES_VARIANT_PARAMETER: u64 = 2;
pub const BCB_WRAPPED_KEY_PARAMETER: u64 = 3;
pub const AAD_SCOPE_FLAGS_PARAMETER: u64 = 4;

// Security result id of the authentication tag (RFC 9173 4.4)
pub const AUTHENTICATION_TAG_RESULT: u64 = 1;

/// Security context parameters of BCB-AES-GCM, all of them are optional
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BcbSecurityContextParameter {
    pub iv: Option<Vec<u8>>,
    pub aes_variant: Option<AesVariantType>,
    pub wrapped_key: Option<Vec<u8>>,
    pub aad_scope_flags: Option<AadScopeFlagsType>,
}

impl SecurityContextParameters for BcbSecurityContextParameter {
    fn to_parameters(&self) -> Vec<SecurityParameter> {
        let mut params = Vec::new();
        if let Some(iv) = &self.iv {
            params.push((IV_PARAMETER, Value::Bytes(iv.clone())));
        }
        if let Some(variant) = self.aes_variant {
            params.push((AES_VARIANT_PARAMETER, Value::Integer(variant.into())));
        }
        if let Some(key) = &self.wrapped_key {
            params.push((BCB_WRAPPED_KEY_PARAMETER, Value::Bytes(key.clone())));
        }
        if let Some(flags) = self.aad_scope_flags {
            params.push((AAD_SCOPE_FLAGS_PARAMETER, Value::Integer(flags.into())));
        }
        params
    }

    fn from_parameters(parameters: &[SecurityParameter]) -> Result<Self, BpsecError> {
        let mut result = BcbSecurityContextParameter::default();
        for (id, value) in parameters {
            let invalid = || BpsecError::InvalidParameter(*id);
            match (*id, value) {
                (IV_PARAMETER, Value::Bytes(iv)) => result.iv = Some(iv.clone()),
                (AES_VARIANT_PARAMETER, Value::Integer(v)) => {
                    result.aes_variant = Some(AesVariantType::try_from(*v).map_err(|_| invalid())?);
                }
                (BCB_WRAPPED_KEY_PARAMETER, Value::Bytes(key)) => {
                    result.wrapped_key = Some(key.clone())
                }
                (AAD_SCOPE_FLAGS_PARAMETER, Value::Integer(v)) => {
                    result.aad_scope_flags =
                        Some(AadScopeFlagsType::try_from(*v).map_err(|_| invalid())?);
                }
                (IV_PARAMETER..=AAD_SCOPE_FLAGS_PARAMETER, _) => return Err(invalid()),
                _ => return Err(BpsecError::UnknownParameter(*id)),
            }
        }
        Ok(result)
    }
}
