//! Block confidentiality block ([RFC 9172 3.8](https://www.rfc-editor.org/rfc/rfc9172.html#name-block-confidentiality-block))
//!
//! The block-type-specific data of a BCB is an abstract security block, the
//! security operations are defined by security contexts such as BCB-AES-GCM
//! in [`crate::bpsec::rfc9173::bcb`].

use crate::bundle::ByteBuffer;
use crate::canonical::{CanonicalBlock, CanonicalBlockBuilder, CanonicalData};
use crate::flags::BlockControlFlags;

use super::*;

/// Abstract security block of a BCB
pub type ConfidentialityBlock = AbstractSecurityBlock;

/// Create a BCB canonical block carrying the given encoded abstract security block.
///
/// As BCBs must be replicated in every fragment (RFC 9172 3.8), the block
/// processing control flags of the block include `BLOCK_REPLICATE`.
pub fn new_confidentiality_block(
    block_number: u64,
    bcf: BlockControlFlags,
    security_block: ByteBuffer,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(CONFIDENTIALITY_BLOCK)
        .block_number(block_number)
        .block_control_flags((bcf | BlockControlFlags::BLOCK_REPLICATE).bits())
        .data(CanonicalData::Unknown(security_block))
        .build()
        .unwrap()
}
