//! Block integrity block ([RFC 9172 3.7](https://www.rfc-editor.org/rfc/rfc9172.html#name-block-integrity-block))
//!
//! The block-type-specific data of a BIB is an abstract security block, the
//! security operations are defined by security contexts such as BIB-HMAC-SHA2
//! in [`crate::bpsec::rfc9173::bib`].

use crate::bundle::ByteBuffer;
use crate::canonical::{CanonicalBlock, CanonicalBlockBuilder, CanonicalData};
use crate::flags::BlockControlFlags;

use super::*;

/// Abstract security block of a BIB
pub type IntegrityBlock = AbstractSecurityBlock;
/// Builder for the abstract security block of a BIB
pub type IntegrityBlockBuilder = SecurityBlockBuilder;
pub type IntegrityBlockBuilderError = BpsecError;

/// Create a BIB canonical block carrying the given encoded abstract security block
pub fn new_integrity_block(
    block_number: u64,
    bcf: BlockControlFlags,
    security_block: ByteBuffer,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(INTEGRITY_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf.bits())
        .data(CanonicalData::Unknown(security_block)) // The deserializer doesn't know the integrity block type, with no changes made this also has to be encoded as Unknown
        .build()
        .unwrap()
}
