//! Abstract security block ([RFC 9172 3.6](https://www.rfc-editor.org/rfc/rfc9172.html#name-abstract-security-block)),
//! the common structure of block integrity and block confidentiality blocks.
//!
//! Security context parameters and results are kept as generic pairs of id and
//! cbor value, as their types are defined by each security context. Security
//! contexts provide typed views on them, e.g., via [`SecurityContextParameters`].

use serde::Deserialize;
use serde_cbor::Value;
use thiserror::Error;

use super::*;
use crate::bundle::ByteBuffer;
use crate::eid::EndpointID;

/// Security context parameter as pair of parameter id and value (RFC 9172 3.6)
pub type SecurityParameter = (u64, Value);
/// Security result as pair of result id and value (RFC 9172 3.6)
pub type SecurityResult = (u64, Value);

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum BpsecError {
    #[error("security blocks must have at least one security target")]
    MissingSecurityTargets,
    #[error("expected one non-empty set of security results per security target")]
    ResultsMismatch,
    #[error("reserved security context flags are set: {0:#x}")]
    ReservedFlags(SecurityContextFlag),
    #[error("unknown security context parameter {0}")]
    UnknownParameter(u64),
    #[error("invalid value for security context parameter {0}")]
    InvalidParameter(u64),
    #[error("no security operation input given for security target {0}")]
    MissingTargetInput(u64),
    #[error("block {0} is not a security target")]
    UnknownTarget(u64),
    #[error("block {0} does not exist")]
    MissingBlock(u64),
    #[error("block {0} can not be a security target: {1}")]
    InvalidTarget(u64, String),
    #[error("missing security context parameter {0}")]
    MissingParameter(u64),
    #[error("missing security result for security target {0}")]
    MissingResult(u64),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("security operation failed: {0}")]
    OperationFailed(String),
    #[error("unsupported security context feature: {0}")]
    Unsupported(String),
    #[error("cbor error: {0}")]
    Cbor(#[from] serde_cbor::Error),
}

/// Typed security context parameters of a security context, converted from and to
/// the generic parameters of an abstract security block.
pub trait SecurityContextParameters: Sized {
    fn to_parameters(&self) -> Vec<SecurityParameter>;
    fn from_parameters(parameters: &[SecurityParameter]) -> Result<Self, BpsecError>;
}

/// Abstract security block, the block-type-specific data of BIBs and BCBs.
#[derive(Debug, Clone, PartialEq)]
pub struct AbstractSecurityBlock {
    /// Block numbers of the security targets
    pub security_targets: Vec<u64>,
    pub security_context_id: SecurityContextId,
    pub security_source: EndpointID,
    /// Security context parameters, their presence is indicated by the security context flags
    pub security_context_parameters: Option<Vec<SecurityParameter>>,
    /// One set of results per security target, in the order of the security targets
    pub security_results: Vec<Vec<SecurityResult>>,
}

impl AbstractSecurityBlock {
    pub fn new() -> AbstractSecurityBlock {
        AbstractSecurityBlock {
            security_targets: Vec::new(),
            security_context_id: BIB_HMAC_SHA2_ID,
            security_source: EndpointID::none(),
            security_context_parameters: None,
            security_results: Vec::new(),
        }
    }

    /// Security context flags, derived from the presence of security context parameters
    pub fn security_context_flags(&self) -> SecurityContextFlag {
        if self.security_context_parameters.is_some() {
            SEC_CONTEXT_PRESENT
        } else {
            SEC_CONTEXT_ABSENT
        }
    }

    /// Typed security context parameters, if present
    pub fn parameters<P: SecurityContextParameters>(&self) -> Result<Option<P>, BpsecError> {
        self.security_context_parameters
            .as_deref()
            .map(P::from_parameters)
            .transpose()
    }

    /// Set typed security context parameters
    pub fn set_parameters<P: SecurityContextParameters>(&mut self, parameters: &P) {
        self.security_context_parameters = Some(parameters.to_parameters());
    }

    /// Security results of the given security target
    pub fn results(&self, target: u64) -> Option<&[SecurityResult]> {
        let index = self.security_targets.iter().position(|t| *t == target)?;
        self.security_results.get(index).map(Vec::as_slice)
    }

    /// Value of a security result of the given security target
    pub fn result(&self, target: u64, result_id: u64) -> Option<&Value> {
        self.results(target)?
            .iter()
            .find(|(id, _)| *id == result_id)
            .map(|(_, value)| value)
    }

    /// Encode the abstract security block as CBOR sequence (RFC 9172 3.6)
    pub fn to_cbor(&self) -> ByteBuffer {
        let mut buf = Vec::new();
        let encode_error = "Error encoding abstract security block";
        serde_cbor::to_writer(&mut buf, &self.security_targets).expect(encode_error);
        serde_cbor::to_writer(&mut buf, &self.security_context_id).expect(encode_error);
        serde_cbor::to_writer(&mut buf, &self.security_context_flags()).expect(encode_error);
        serde_cbor::to_writer(&mut buf, &self.security_source).expect(encode_error);
        if let Some(params) = &self.security_context_parameters {
            serde_cbor::to_writer(&mut buf, params).expect(encode_error);
        }
        serde_cbor::to_writer(&mut buf, &self.security_results).expect(encode_error);
        buf
    }

    /// Decode the abstract security block from its encoding as CBOR sequence (RFC 9172 3.6),
    /// as found in the block-type-specific data of a BIB or BCB.
    pub fn from_cbor(data: &[u8]) -> Result<AbstractSecurityBlock, BpsecError> {
        let mut de = serde_cbor::Deserializer::from_slice(data);

        let security_targets: Vec<u64> = Deserialize::deserialize(&mut de)?;
        let security_context_id = Deserialize::deserialize(&mut de)?;
        let security_context_flags: SecurityContextFlag = Deserialize::deserialize(&mut de)?;
        let security_source = Deserialize::deserialize(&mut de)?;
        let security_context_parameters = if security_context_flags & SEC_CONTEXT_PRESENT != 0 {
            Some(Deserialize::deserialize(&mut de)?)
        } else {
            None
        };
        let security_results: Vec<Vec<SecurityResult>> = Deserialize::deserialize(&mut de)?;
        de.end()?;

        // bits 1-7 of the security context flags are reserved
        if security_context_flags & !SEC_CONTEXT_PRESENT != 0 {
            return Err(BpsecError::ReservedFlags(security_context_flags));
        }
        if security_targets.is_empty() {
            return Err(BpsecError::MissingSecurityTargets);
        }
        // every security operation has at least one result for its target
        if security_results.len() != security_targets.len()
            || security_results.iter().any(Vec::is_empty)
        {
            return Err(BpsecError::ResultsMismatch);
        }

        Ok(AbstractSecurityBlock {
            security_targets,
            security_context_id,
            security_source,
            security_context_parameters,
            security_results,
        })
    }
}

impl Default for AbstractSecurityBlock {
    fn default() -> Self {
        AbstractSecurityBlock::new()
    }
}

/// Builder for abstract security blocks of BIBs and BCBs.
///
/// The security context defaults to BIB-HMAC-SHA2.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityBlockBuilder {
    asb: AbstractSecurityBlock,
}

impl SecurityBlockBuilder {
    pub fn new() -> SecurityBlockBuilder {
        SecurityBlockBuilder {
            asb: AbstractSecurityBlock::new(),
        }
    }
    pub fn security_targets(mut self, security_targets: Vec<u64>) -> Self {
        self.asb.security_targets = security_targets;
        self
    }
    pub fn security_context_id(mut self, security_context_id: SecurityContextId) -> Self {
        self.asb.security_context_id = security_context_id;
        self
    }
    pub fn security_source(mut self, security_source: EndpointID) -> Self {
        self.asb.security_source = security_source;
        self
    }
    /// Set typed security context parameters of a security context
    pub fn security_context_parameters<P: SecurityContextParameters>(
        mut self,
        security_context_parameters: P,
    ) -> Self {
        self.asb.set_parameters(&security_context_parameters);
        self
    }
    /// Set generic security context parameters
    pub fn parameters(mut self, parameters: Vec<SecurityParameter>) -> Self {
        self.asb.security_context_parameters = Some(parameters);
        self
    }
    pub fn security_results(mut self, security_results: Vec<Vec<SecurityResult>>) -> Self {
        self.asb.security_results = security_results;
        self
    }
    pub fn build(self) -> Result<AbstractSecurityBlock, BpsecError> {
        if self.asb.security_targets.is_empty() {
            return Err(BpsecError::MissingSecurityTargets);
        }
        Ok(self.asb)
    }
}

impl Default for SecurityBlockBuilder {
    fn default() -> Self {
        SecurityBlockBuilder::new()
    }
}
