//! Bundle Protocol Security (BPSec, [RFC 9172](https://www.rfc-editor.org/rfc/rfc9172.html))
//!
//! The code is structured in layers, so that further security blocks and
//! security contexts, e.g., COSE, can be added without changing the core:
//!
//! * [`asb`]: the abstract security block, the structure shared by all security
//!   blocks, with generic security context parameters and results
//! * [`bib`] and [`bcb`]: the block integrity and block confidentiality blocks
//! * [`rfc9173`]: the default security contexts BIB-HMAC-SHA2 and BCB-AES-GCM,
//!   which define the types of their parameters and results and the security
//!   operations

pub mod asb;
pub mod bcb;
pub mod bib;
pub mod rfc9173;

pub use asb::*;
pub use bcb::*;
pub use bib::*;
pub use rfc9173::bcb::*;
pub use rfc9173::bib::*;
pub use rfc9173::{unwrap_key, wrap_key};

use crate::crc::{CrcBlock, CrcRawType};
use crate::*;

// https://www.rfc-editor.org/rfc/rfc9172.html#BlockType
pub const INTEGRITY_BLOCK: CanonicalBlockType = 11;
pub const CONFIDENTIALITY_BLOCK: CanonicalBlockType = 12;

// Security Context Id
// https://www.rfc-editor.org/rfc/rfc9173.html#name-security-context-identifier
// https://www.rfc-editor.org/rfc/rfc9172.html#SecCtx
pub type SecurityContextId = i16;
pub const BIB_HMAC_SHA2_ID: SecurityContextId = 1; // BIB-HMAC-SHA2
pub const BCB_AES_GCM_ID: SecurityContextId = 2; // BCB-AES-GCM

// Security Context Flags
//
pub type SecurityContextFlag = u8;
pub const SEC_CONTEXT_ABSENT: SecurityContextFlag = 0; // Security context parameters should be empty
pub const SEC_CONTEXT_PRESENT: SecurityContextFlag = 1; // Security context parameters are defined

pub type SecurityBlockHeader = (CanonicalBlockType, u64, flags::BlockControlFlagsType);

/// Insert a new security block after the primary block and the security blocks added
/// before, as in the examples of RFC 9173, keeping the payload block last
pub(crate) fn insert_security_block(bundle: &mut Bundle, block: CanonicalBlock) {
    let position = bundle
        .canonicals
        .iter()
        .take_while(|b| b.block_type == INTEGRITY_BLOCK || b.block_type == CONFIDENTIALITY_BLOCK)
        .count();
    bundle.canonicals.insert(position, block);
}

/// Remove a block from a bundle together with the security operations targeting it. Security
/// blocks without remaining security operations are removed as well (RFC 9172 5.1.1, 5.1.2).
///
/// The other security operations stay valid, as security targets are not part of the
/// IPPT or AAD of BIB-HMAC-SHA2 and BCB-AES-GCM. The primary block and BCBs can't be
/// removed, a BCB is removed when it is decrypted or all its targets are removed.
pub fn remove_block(bundle: &mut Bundle, block_number: u64) -> Result<(), BpsecError> {
    if block_number == 0 {
        return Err(BpsecError::InvalidTarget(
            0,
            "the primary block can't be removed".to_string(),
        ));
    }
    let block = bundle
        .canonicals
        .iter()
        .find(|b| b.block_number == block_number)
        .ok_or(BpsecError::MissingBlock(block_number))?;
    if block.block_type == CONFIDENTIALITY_BLOCK {
        return Err(BpsecError::InvalidTarget(
            block_number,
            "BCBs can't be removed without decrypting their targets".to_string(),
        ));
    }
    let mut removed = vec![block_number];
    while let Some(number) = removed.pop() {
        bundle.canonicals.retain(|b| b.block_number != number);
        for block_type in [INTEGRITY_BLOCK, CONFIDENTIALITY_BLOCK] {
            for (security_block_number, mut asb) in bundle.security_blocks(block_type) {
                let Some(index) = asb.security_targets.iter().position(|t| *t == number) else {
                    continue;
                };
                asb.security_targets.remove(index);
                asb.security_results.remove(index);
                if asb.security_targets.is_empty() {
                    removed.push(security_block_number);
                } else if let Some(security_block) = bundle
                    .canonicals
                    .iter_mut()
                    .find(|b| b.block_number == security_block_number)
                {
                    security_block.set_data(CanonicalData::Unknown(asb.to_cbor()));
                }
            }
        }
    }
    Ok(())
}

/// Check that `crc_type` is a known CRC type before a bundle is changed
pub(crate) fn check_crc_type(crc_type: CrcRawType) -> Result<(), BpsecError> {
    use crate::crc::{CRC_16, CRC_32, CRC_NO};
    if [CRC_NO, CRC_16, CRC_32].contains(&crc_type) {
        Ok(())
    } else {
        Err(BpsecError::Unsupported(format!("CRC type {}", crc_type)))
    }
}

/// Add a CRC of `crc_type` to the targets of a security operation removed by its security
/// acceptor, that are not the security target of another security block (RFC 9173 3.8.2,
/// 4.8.2). A security acceptor that is the bundle destination may pass `CRC_NO`.
pub(crate) fn restore_target_crcs(bundle: &mut Bundle, targets: &[u64], crc_type: CrcRawType) {
    if crc_type == crate::crc::CRC_NO {
        return;
    }
    let protected: Vec<u64> = bundle
        .decode_bibs()
        .iter()
        .chain(bundle.decode_bcbs().iter())
        .flat_map(|b| b.security_targets.iter().copied())
        .collect();
    for target in targets.iter().filter(|t| !protected.contains(t)) {
        if *target == 0 {
            bundle.primary.set_crc_type(crc_type);
        } else if let Some(block) = bundle
            .canonicals
            .iter_mut()
            .find(|b| b.block_number == *target)
        {
            block.set_crc_type(crc_type);
        }
    }
}
