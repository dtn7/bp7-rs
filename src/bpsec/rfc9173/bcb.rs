//! BCB-AES-GCM security context ([RFC 9173 4](https://www.rfc-editor.org/rfc/rfc9173.html#name-security-context-bcb-aes-gc))
//!
//! [`encrypt`] encrypts a block of a bundle in place and adds a BCB for the
//! security operation, [`decrypt`] decrypts the targets of a BCB and removes it.
//! If the BCB has a wrapped key, the key given to both is the key encryption key
//! to unwrap the content encryption key, see [`super::wrap_key`].
//!
//! Based on the BCB implementation of Lucien Loiseau (dtn7/bp7-rs#19).

use aes_gcm::AesGcm;
use aes_gcm::aead::consts::{U8, U9, U10, U11, U12, U13, U14, U15, U16};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::{Aes128, Aes256};
use bitflags::bitflags;
use serde_cbor::Value;

use crate::bpsec::*;
use crate::bundle::{Bundle, ByteBuffer};
use crate::canonical::{
    BUNDLE_AGE_BLOCK, CanonicalBlock, CanonicalData, HOP_COUNT_BLOCK, PAYLOAD_BLOCK,
    PREVIOUS_NODE_BLOCK,
};
use crate::crc::{CRC_NO, CrcBlock, CrcRawType};
use crate::eid::EndpointID;
use crate::flags::BlockControlFlags;
use crate::primary::PrimaryBlock;

// AES Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aes-gcm
pub type AesVariantType = u16;
pub const AES_128_GCM: AesVariantType = 1;
pub const AES_256_GCM: AesVariantType = 3; // default

// AAD Scope Flags
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aad-scope-flags
pub type AadScopeFlagsType = u16;

bitflags! {
    pub struct AadScopeFlags: AadScopeFlagsType {
        // Include primary block flag
        const AAD_PRIMARY_BLOCK = 0x0001;
        // Include target header flag
        const AAD_TARGET_HEADER = 0x0002;
        // Include security header flag
        const AAD_SECURITY_HEADER = 0x0004;
    }
}

/// AAD scope flags assumed if not given, all assigned flags (RFC 9173 4.3.4)
pub const DEFAULT_AAD_SCOPE_FLAGS: AadScopeFlagsType = 0x0007;

/// Recommended length of the initialization vector, IVs of 8 to 16 bytes are
/// supported (RFC 9173 4.3.1)
pub const IV_LEN: usize = 12;

/// Length of the authentication tag, always 128 bits (RFC 9173 4.3.2)
pub const AUTHENTICATION_TAG_LEN: usize = 16;

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

/// Additional authenticated data of a security target (RFC 9173 4.7.2)
pub fn additional_authenticated_data(
    scope_flags: AadScopeFlagsType,
    primary_block: &PrimaryBlock,
    target_block: &CanonicalBlock,
    security_header: SecurityBlockHeader,
) -> ByteBuffer {
    let encode_error = "Error encoding additional authenticated data";
    let flags = AadScopeFlags::from_bits_truncate(scope_flags);
    // the scope flags are always included, with reserved and unassigned bits set to 0
    let mut aad = serde_cbor::to_vec(&flags.bits()).expect(encode_error);
    if flags.contains(AadScopeFlags::AAD_PRIMARY_BLOCK) {
        serde_cbor::to_writer(&mut aad, primary_block).expect(encode_error);
    }
    if flags.contains(AadScopeFlags::AAD_TARGET_HEADER) {
        serde_cbor::to_writer(&mut aad, &target_block.block_type).expect(encode_error);
        serde_cbor::to_writer(&mut aad, &target_block.block_number).expect(encode_error);
        serde_cbor::to_writer(&mut aad, &target_block.block_control_flags).expect(encode_error);
    }
    if flags.contains(AadScopeFlags::AAD_SECURITY_HEADER) {
        serde_cbor::to_writer(&mut aad, &security_header.0).expect(encode_error);
        serde_cbor::to_writer(&mut aad, &security_header.1).expect(encode_error);
        serde_cbor::to_writer(&mut aad, &security_header.2).expect(encode_error);
    }
    aad
}

/// Content of the block-type-specific data of a block, i.e., its plaintext or
/// ciphertext (RFC 9173 4.7.1)
fn block_type_specific_data(block: &CanonicalBlock) -> ByteBuffer {
    match block.data() {
        CanonicalData::Data(data) | CanonicalData::Unknown(data) => data.clone(),
        other => other.to_cbor(),
    }
}

/// Replace the block-type-specific data of a block
fn set_block_type_specific_data(block: &mut CanonicalBlock, data: ByteBuffer) {
    if block.block_type == PAYLOAD_BLOCK {
        block.set_data(CanonicalData::Data(data));
    } else {
        block.set_data(CanonicalData::Unknown(data));
    }
}

/// AES-GCM with an AES variant and key, for IVs of 8 to 16 bytes
struct AesGcmCipher {
    variant: AesVariantType,
    key: ByteBuffer,
}

/// Encrypt or decrypt with an AES-GCM cipher of a key and IV size
fn run_aes_gcm<C: KeyInit + Aead>(
    key: &[u8],
    iv: &[u8],
    msg: &[u8],
    aad: &[u8],
    encrypt: bool,
) -> Result<ByteBuffer, BpsecError> {
    let cipher = C::new_from_slice(key)
        .map_err(|_| BpsecError::InvalidKey("invalid key length".to_string()))?;
    let nonce = aes_gcm::aead::Nonce::<C>::from_slice(iv);
    let payload = Payload { msg, aad };
    if encrypt {
        cipher
            .encrypt(nonce, payload)
            .map_err(|_| BpsecError::OperationFailed("encryption failed".to_string()))
    } else {
        cipher.decrypt(nonce, payload).map_err(|_| {
            BpsecError::OperationFailed("decryption or authentication failed".to_string())
        })
    }
}

/// Select the AES-GCM cipher for the size of the IV
macro_rules! aes_gcm_for_iv {
    ($aes:ty, $key:expr, $iv:expr, $msg:expr, $aad:expr, $encrypt:expr) => {
        match $iv.len() {
            8 => run_aes_gcm::<AesGcm<$aes, U8>>($key, $iv, $msg, $aad, $encrypt),
            9 => run_aes_gcm::<AesGcm<$aes, U9>>($key, $iv, $msg, $aad, $encrypt),
            10 => run_aes_gcm::<AesGcm<$aes, U10>>($key, $iv, $msg, $aad, $encrypt),
            11 => run_aes_gcm::<AesGcm<$aes, U11>>($key, $iv, $msg, $aad, $encrypt),
            12 => run_aes_gcm::<AesGcm<$aes, U12>>($key, $iv, $msg, $aad, $encrypt),
            13 => run_aes_gcm::<AesGcm<$aes, U13>>($key, $iv, $msg, $aad, $encrypt),
            14 => run_aes_gcm::<AesGcm<$aes, U14>>($key, $iv, $msg, $aad, $encrypt),
            15 => run_aes_gcm::<AesGcm<$aes, U15>>($key, $iv, $msg, $aad, $encrypt),
            16 => run_aes_gcm::<AesGcm<$aes, U16>>($key, $iv, $msg, $aad, $encrypt),
            _ => Err(BpsecError::InvalidParameter(IV_PARAMETER)),
        }
    };
}

impl AesGcmCipher {
    fn new(variant: AesVariantType, key: &[u8]) -> Result<Self, BpsecError> {
        let expected_len = match variant {
            AES_128_GCM => 16,
            AES_256_GCM => 32,
            _ => return Err(BpsecError::Unsupported(format!("AES variant {}", variant))),
        };
        if key.len() != expected_len {
            return Err(BpsecError::InvalidKey(format!(
                "expected {} bytes",
                expected_len
            )));
        }
        Ok(AesGcmCipher {
            variant,
            key: key.to_vec(),
        })
    }

    fn apply(
        &self,
        iv: &[u8],
        msg: &[u8],
        aad: &[u8],
        encrypt: bool,
    ) -> Result<ByteBuffer, BpsecError> {
        if self.variant == AES_128_GCM {
            aes_gcm_for_iv!(Aes128, &self.key, iv, msg, aad, encrypt)
        } else {
            aes_gcm_for_iv!(Aes256, &self.key, iv, msg, aad, encrypt)
        }
    }

    /// Encrypt a plaintext, returning ciphertext and authentication tag
    fn encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(ByteBuffer, ByteBuffer), BpsecError> {
        let mut ciphertext = self.apply(iv, plaintext, aad, true)?;
        // AES-GCM produces the ciphertext followed by the authentication tag
        let tag = ciphertext.split_off(ciphertext.len() - AUTHENTICATION_TAG_LEN);
        Ok((ciphertext, tag))
    }

    /// Decrypt and authenticate a ciphertext
    fn decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<ByteBuffer, BpsecError> {
        let mut msg = Vec::with_capacity(ciphertext.len() + tag.len());
        msg.extend_from_slice(ciphertext);
        msg.extend_from_slice(tag);
        self.apply(iv, &msg, aad, false)
    }
}

/// IVs must have 8 to 16 bytes (RFC 9173 4.3.1)
fn check_iv(iv: &[u8]) -> Result<(), BpsecError> {
    if !(8..=16).contains(&iv.len()) {
        return Err(BpsecError::InvalidParameter(IV_PARAMETER));
    }
    Ok(())
}

/// Encrypt a block of a bundle in place with BCB-AES-GCM (RFC 9173 4.8.1) and add a BCB
/// for this security operation to the bundle. Returns the block number of the new BCB.
///
/// The AES variant, AAD scope flags and wrapped key are taken from `parameters`, AES-256-GCM
/// and all AAD scope flags are used if not given. The IV is set as parameter of the BCB.
///
/// **An IV must never be used more than once with the same key**, as this breaks the
/// confidentiality and integrity of all bundles encrypted with this key and IV
/// (RFC 9173 4.6). As the IV is a parameter shared by all targets of a BCB, every
/// encrypted block gets its own BCB.
///
/// If `parameters` contain a wrapped key, `key` is the key encryption key to unwrap the
/// content encryption key, otherwise the content encryption key itself.
///
/// The CRC of the target block is removed and the CRC of the primary block calculated,
/// as it may be part of the additional authenticated data.
pub fn encrypt(
    bundle: &mut Bundle,
    target: u64,
    key: &[u8],
    iv: &[u8],
    security_source: EndpointID,
    mut parameters: BcbSecurityContextParameter,
) -> Result<u64, BpsecError> {
    let key = super::operation_key(key, parameters.wrapped_key.as_deref())?;
    let cipher = AesGcmCipher::new(parameters.aes_variant.unwrap_or(AES_256_GCM), &key)?;
    check_iv(iv)?;
    let aad_scope_flags = parameters
        .aad_scope_flags
        .unwrap_or(DEFAULT_AAD_SCOPE_FLAGS);
    // reserved and unassigned bits must be 0 (RFC 9173 4.3.4)
    if AadScopeFlags::from_bits(aad_scope_flags).is_none() {
        return Err(BpsecError::InvalidParameter(AAD_SCOPE_FLAGS_PARAMETER));
    }

    let target_block = bundle
        .canonicals
        .iter()
        .find(|b| b.block_number == target)
        .ok_or(BpsecError::MissingBlock(target))?;
    // allowed targets of BCBs (RFC 9172 3.8)
    let invalid_target = |reason: &str| Err(BpsecError::InvalidTarget(target, reason.to_string()));
    match target_block.block_type {
        CONFIDENTIALITY_BLOCK => return invalid_target("BCBs must not be encrypted"),
        INTEGRITY_BLOCK => {
            return invalid_target("BIBs must be encrypted by a BCB with their targets");
        }
        // their encrypted content could not be decoded anymore
        HOP_COUNT_BLOCK | BUNDLE_AGE_BLOCK | PREVIOUS_NODE_BLOCK => {
            return Err(BpsecError::Unsupported(format!(
                "encryption of blocks of type {}",
                target_block.block_type
            )));
        }
        _ => {}
    }

    // a target must not be encrypted by more than one BCB (RFC 9172 3.2)
    if bundle
        .decode_bcbs()
        .iter()
        .any(|bcb| bcb.security_targets.contains(&target))
    {
        return Err(BpsecError::InvalidTarget(
            target,
            "already a security target of a BCB".to_string(),
        ));
    }
    // a BIB of the target would have to be encrypted by the same BCB (RFC 9172 3.9),
    // which would require multiple targets sharing the IV of this BCB
    if bundle
        .decode_bibs()
        .iter()
        .any(|bib| bib.security_targets.contains(&target))
    {
        return Err(BpsecError::Unsupported(format!(
            "encryption of block {}, which is a security target of a BIB",
            target
        )));
    }

    let bcb_block_number = bundle.next_canonical_block_number();
    let bcb_flags = BlockControlFlags::BLOCK_REPLICATE.bits();
    // the primary block is part of the AAD with its final CRC
    bundle.primary.update_crc();

    let primary = &bundle.primary;
    let target_block = bundle
        .canonicals
        .iter_mut()
        .find(|b| b.block_number == target)
        .expect("target block was found before");
    target_block.set_crc_type(CRC_NO);
    let aad = additional_authenticated_data(
        aad_scope_flags,
        primary,
        target_block,
        (CONFIDENTIALITY_BLOCK, bcb_block_number, bcb_flags),
    );
    let (ciphertext, tag) = cipher.encrypt(iv, &block_type_specific_data(target_block), &aad)?;
    set_block_type_specific_data(target_block, ciphertext);

    parameters.iv = Some(iv.to_vec());
    let bcb = SecurityBlockBuilder::default()
        .security_targets(vec![target])
        .security_context_id(BCB_AES_GCM_ID)
        .security_source(security_source)
        .security_context_parameters(parameters)
        .security_results(vec![vec![(AUTHENTICATION_TAG_RESULT, Value::Bytes(tag))]])
        .build()?;
    insert_security_block(
        bundle,
        new_confidentiality_block(
            bcb_block_number,
            BlockControlFlags::from_bits_truncate(bcb_flags),
            bcb.to_cbor(),
        ),
    );
    Ok(bcb_block_number)
}

/// Decrypt the security targets of a BCB-AES-GCM BCB in place (RFC 9173 4.8.2) and remove
/// the BCB from the bundle.
///
/// If the BCB has a wrapped key, `key` is the key encryption key to unwrap the content
/// encryption key, otherwise the content encryption key itself. The bundle is only changed
/// if all targets are decrypted and authenticated successfully.
///
/// If the security acceptor is not the bundle destination, targets without other security
/// operations get a CRC of `crc_type` (RFC 9173 4.8.2), the bundle destination may pass
/// `CRC_NO`.
pub fn decrypt(
    bundle: &mut Bundle,
    bcb_block_number: u64,
    key: &[u8],
    crc_type: CrcRawType,
) -> Result<(), BpsecError> {
    check_crc_type(crc_type)?;
    let bcb_block = bundle
        .canonicals
        .iter()
        .find(|b| b.block_number == bcb_block_number && b.block_type == CONFIDENTIALITY_BLOCK)
        .ok_or(BpsecError::MissingBlock(bcb_block_number))?;
    let bcb = match bcb_block.data() {
        CanonicalData::Unknown(data) => ConfidentialityBlock::from_cbor(data)?,
        _ => return Err(BpsecError::MissingBlock(bcb_block_number)),
    };
    if bcb.security_context_id != BCB_AES_GCM_ID {
        return Err(BpsecError::Unsupported(format!(
            "security context {}",
            bcb.security_context_id
        )));
    }
    let parameters: BcbSecurityContextParameter = bcb.parameters()?.unwrap_or_default();
    let iv = parameters
        .iv
        .ok_or(BpsecError::MissingParameter(IV_PARAMETER))?;
    check_iv(&iv)?;
    let key = super::operation_key(key, parameters.wrapped_key.as_deref())?;
    let cipher = AesGcmCipher::new(parameters.aes_variant.unwrap_or(AES_256_GCM), &key)?;
    let aad_scope_flags = parameters
        .aad_scope_flags
        .unwrap_or(DEFAULT_AAD_SCOPE_FLAGS);
    let security_header = (
        bcb_block.block_type,
        bcb_block.block_number,
        bcb_block.block_control_flags,
    );

    let mut plaintexts = Vec::with_capacity(bcb.security_targets.len());
    for target in &bcb.security_targets {
        let target_block = bundle
            .canonicals
            .iter()
            .find(|b| b.block_number == *target)
            .ok_or(BpsecError::MissingBlock(*target))?;
        let data = block_type_specific_data(target_block);
        let (ciphertext, tag) = match bcb.result(*target, AUTHENTICATION_TAG_RESULT) {
            Some(Value::Bytes(tag)) if tag.len() == AUTHENTICATION_TAG_LEN => {
                (data.as_slice(), tag.as_slice())
            }
            Some(_) => return Err(BpsecError::MissingResult(*target)),
            // without result, the tag is appended to the ciphertext (RFC 9173 4.4)
            None if data.len() >= AUTHENTICATION_TAG_LEN => {
                data.split_at(data.len() - AUTHENTICATION_TAG_LEN)
            }
            None => return Err(BpsecError::MissingResult(*target)),
        };
        let aad = additional_authenticated_data(
            aad_scope_flags,
            &bundle.primary,
            target_block,
            security_header,
        );
        let plaintext = cipher.decrypt(&iv, ciphertext, tag, &aad)?;
        plaintexts.push((*target, plaintext));
    }

    for (target, plaintext) in plaintexts {
        if let Some(block) = bundle
            .canonicals
            .iter_mut()
            .find(|b| b.block_number == target)
        {
            set_block_type_specific_data(block, plaintext);
        }
    }
    bundle
        .canonicals
        .retain(|b| b.block_number != bcb_block_number);
    restore_target_crcs(bundle, &bcb.security_targets, crc_type);
    Ok(())
}
