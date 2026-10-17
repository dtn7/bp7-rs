//! Bundle Protocol Security (BPSec, [RFC 9172](https://www.rfc-editor.org/rfc/rfc9172.html))
//!
//! Definitions shared by all security blocks and contexts are found here, the
//! block integrity block in [`bib`] and the security contexts of
//! [RFC 9173](https://www.rfc-editor.org/rfc/rfc9173.html) in [`rfc9173`].

pub mod bib;
pub mod rfc9173;

pub use bib::*;
pub use rfc9173::bcb::*;
pub use rfc9173::bib::*;

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
