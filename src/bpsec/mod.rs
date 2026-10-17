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
