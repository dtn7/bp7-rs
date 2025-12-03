//use std::convert::TryInto;
use std::fmt;

use super::bundle::ByteBuffer;
use super::flags::BlockControlFlags;
//use super::flags::BlockControlFlagsType;
use super::primary::PrimaryBlock;
use super::*;

use bitflags::bitflags;
use thiserror::Error;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize, de};

// https://www.rfc-editor.org/rfc/rfc9172.html#BlockType
pub const INTEGRITY_BLOCK: CanonicalBlockType = 11;
pub const CONFIDENTIALITY_BLOCK: CanonicalBlockType = 12;

// SHA Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-sha-variant
pub type ShaVariantType = u16;
pub const HMAC_SHA_256: ShaVariantType = 5;
pub const HMAC_SHA_384: ShaVariantType = 6; // default
pub const HMAC_SHA_512: ShaVariantType = 7;

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

// AES Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-aes-gcm
pub type AesVariantType = u16;
pub const AES_128_GCM: AesVariantType = 1;
pub const AES_256_GCM: AesVariantType = 3; // default

pub type SecurityBlockHeader = (CanonicalBlockType, u64, flags::BlockControlFlagsType);

/// IntegrityProtectedPlaintext Builder. See IntegrityProtectedPlaintext Doc for usage.
#[derive(Debug, Clone, PartialEq)]
pub struct IpptBuilder {
    scope_flags: IntegrityScopeFlagsType,
    // canonical forms
    primary_block: Option<PrimaryBlock>,
    security_header: Option<SecurityBlockHeader>,
    security_target_contents: Vec<u8>,
}

impl IpptBuilder {
    pub fn new() -> IpptBuilder {
        IpptBuilder {
            scope_flags: 0x0007, // default value
            primary_block: None,
            security_header: None,
            security_target_contents: Vec::new(),
        }
    }
    pub fn scope_flags(mut self, scope_flags: IntegrityScopeFlagsType) -> Self {
        self.scope_flags = scope_flags;
        self
    }
    pub fn primary_block(mut self, primary_block: PrimaryBlock) -> Self {
        self.primary_block = Some(primary_block);
        self
    }
    pub fn security_header(mut self, security_header: SecurityBlockHeader) -> Self {
        self.security_header = Some(security_header);
        self
    }
    pub fn security_target_contents(mut self, security_target_contents: Vec<u8>) -> Self {
        self.security_target_contents = security_target_contents;
        self
    }
    pub fn build(self) -> IntegrityProtectedPlaintext {
        IntegrityProtectedPlaintext {
            scope_flags: self.scope_flags,
            primary_block: self.primary_block,
            security_header: self.security_header,
            security_target_contents: self.security_target_contents,
        }
    }
}

/// Structure to hold the Integrity Protected Plaintext. The content
/// of the IPPT is constructed as the concatenation of information
/// whose integrity is being preserved. Can optionally protect the integrity of
/// the primary block, the payload block header, the security block header.
/// The payload of the security target itself is always protected.
///
/// To function correctly the scope_flags have to be set accordingly.  
/// The default value is 0x0007, which means all flags are set. The
/// other options for the scope_flags are:  <br/>
/// Bit 0 (the low-order bit, 0x0001): Include primary block flag  <br/>
/// Bit 1 (0x0002): Include target header flag  <br/>
/// Bit 2 (0x0004): Include security header flag  <br/>
/// Bits 3-15: Unassigned. Do NOT set.  <br/>
///
/// # Fields
/// * `scope_flags` - Bit field
/// * `primary_block` - A reference to the primary block
/// * `security_header` - A tuple with the values of the block_type,
///   the block_number and the block_control_flags
/// * `security_target_contents` - A Vector with the result values
///
/// # RFC references
/// [IPPT](https://www.rfc-editor.org/rfc/rfc9173.html#name-scope)
///
/// # Results
///
/// # Example
/// TODO: example
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IntegrityProtectedPlaintext {
    scope_flags: IntegrityScopeFlagsType,
    // canonical forms
    primary_block: Option<PrimaryBlock>,
    security_header: Option<SecurityBlockHeader>,
    security_target_contents: Vec<u8>,
}

impl IntegrityProtectedPlaintext {
    pub fn new() -> IntegrityProtectedPlaintext {
        IntegrityProtectedPlaintext {
            scope_flags: 0x0007, // default value
            primary_block: None,
            security_header: None,
            security_target_contents: Vec::new(),
        }
    }

    pub fn create(&mut self, payload_block: &CanonicalBlock) -> ByteBuffer {
        // If header data is not none and corresponding flag is set, include in MAC
        let mut optional_ippt_data = Vec::<u8>::new();

        if self
            .scope_flags
            .has_scope_flags(IntegrityScopeFlags::INTEGRITY_PRIMARY_HEADER)
        {
            if let Some(pb) = &self.primary_block {
                optional_ippt_data.append(
                    serde_cbor::to_vec(pb)
                        .expect("Error creating canonical form of primary block")
                        .as_mut(),
                );
            } else {
                eprintln!("Primary header flag set but no primary header given!")
            }
        }
        if self
            .scope_flags
            .has_scope_flags(IntegrityScopeFlags::INTEGRITY_PAYLOAD_HEADER)
        {
            optional_ippt_data.append(
                self.construct_payload_header(payload_block)
                    .expect("Error constructing payload header")
                    .as_mut(),
            );
        }
        if self
            .scope_flags
            .has_scope_flags(IntegrityScopeFlags::INTEGRITY_SECURITY_HEADER)
        {
            if let Some(sh) = &self.security_header {
                optional_ippt_data.append(
                    self.construct_security_header(sh)
                        .expect("Error constructing security header")
                        .as_mut(),
                );
            } else {
                eprintln!("Security header flag set but no security header given!")
            }
        }

        self.security_target_contents = serde_cbor::to_vec(&payload_block.data()).unwrap();

        // create canonical form of other data
        if !matches!(payload_block.data(), CanonicalData::Data(_)) {
            let temp_bytes = serde_bytes::Bytes::new(self.security_target_contents.as_slice());
            self.security_target_contents = serde_cbor::to_vec(&temp_bytes).unwrap();
        }

        let mut ippt = Vec::<u8>::new();
        ippt.append(
            &mut serde_cbor::to_vec(&self.scope_flags)
                .expect("Error creating canonical form of scope flags"),
        );
        ippt.append(&mut optional_ippt_data);
        ippt.append(&mut self.security_target_contents);
        println!("ippt hex {:?}", hexify(&ippt));
        ippt
    }

    fn construct_payload_header(
        &self,
        payload_block: &CanonicalBlock,
    ) -> Result<ByteBuffer, serde_cbor::Error> {
        let mut header = Vec::<u8>::new();
        header.append(&mut serde_cbor::to_vec(&payload_block.block_type)?);
        header.append(&mut serde_cbor::to_vec(&payload_block.block_number)?);
        header.append(&mut serde_cbor::to_vec(&payload_block.block_control_flags)?);
        //header.append(&mut serde_cbor::to_vec(&payload_block.crc.to_code())?); //TODO: check if not needed?
        Ok(header)
    }

    fn construct_security_header(
        &self,
        security_block_parameter: &SecurityBlockHeader,
    ) -> Result<ByteBuffer, serde_cbor::Error> {
        let mut header = Vec::<u8>::new();
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.0)?);
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.1)?);
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.2)?);
        Ok(header)
    }
}

impl Default for IntegrityProtectedPlaintext {
    fn default() -> Self {
        IntegrityProtectedPlaintext::new()
    }
}

impl Default for IpptBuilder {
    fn default() -> Self {
        IpptBuilder::new()
    }
}

// Integrity Scope Flags
// https://www.rfc-editor.org/rfc/rfc9173.html#name-integrity-scope-flags
pub type IntegrityScopeFlagsType = u16;

bitflags! {
    pub struct IntegrityScopeFlags: IntegrityScopeFlagsType {
        // Include primary block flag
        const INTEGRITY_PRIMARY_HEADER = 0x0001;
        // Include target header flag
        const INTEGRITY_PAYLOAD_HEADER = 0x0002;
        // Include security header flag
        const INTEGRITY_SECURITY_HEADER = 0x0004;
    }
}

pub trait ScopeValidation {
    fn scope_flags(&self) -> IntegrityScopeFlags;
    fn has_scope_flags(&self, flags: IntegrityScopeFlags) -> bool;
}
impl ScopeValidation for IntegrityScopeFlagsType {
    fn scope_flags(&self) -> IntegrityScopeFlags {
        IntegrityScopeFlags::from_bits_truncate(*self)
    }
    fn has_scope_flags(&self, flags: IntegrityScopeFlags) -> bool
    where
        Self: Sized,
    {
        self.scope_flags().contains(flags)
    }
}

// Abstract Security Block
// https://www.rfc-editor.org/rfc/rfc9172.html#name-abstract-security-block

// Security Context Parameters
// https://www.rfc-editor.org/rfc/rfc9173.html#name-enumerations

// Create Builder?
#[derive(Debug, Clone, PartialEq)]
pub struct BibSecurityContextParameter {
    pub sha_variant: Option<(u8, ShaVariantType)>,
    pub wrapped_key: Option<(u8, Vec<u8>)>, // TODO: Wrapped Key //byte string
    pub integrity_scope_flags: Option<(u8, IntegrityScopeFlagsType)>,
}

impl BibSecurityContextParameter {
    pub fn new(
        sha_variant: Option<(u8, ShaVariantType)>,
        wrapped_key: Option<(u8, Vec<u8>)>,
        integrity_scope_flags: Option<(u8, IntegrityScopeFlagsType)>,
    ) -> Self {
        Self {
            sha_variant,
            wrapped_key,
            integrity_scope_flags,
        }
    }
}

impl Default for BibSecurityContextParameter {
    fn default() -> Self {
        BibSecurityContextParameter {
            sha_variant: Some((1, HMAC_SHA_384)),
            wrapped_key: None,
            integrity_scope_flags: Some((3, 0x0007)),
        }
    }
}

impl Serialize for BibSecurityContextParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut num_elems = 0;
        if self.sha_variant.is_some() {
            num_elems += 1
        }
        if self.wrapped_key.is_some() {
            num_elems += 1
        }
        if self.integrity_scope_flags.is_some() {
            num_elems += 1
        }

        let mut seq = serializer.serialize_seq(Some(num_elems))?;

        if let Some(sv) = &self.sha_variant {
            seq.serialize_element(sv)?;
        }
        if let Some(wk) = &self.wrapped_key {
            seq.serialize_element(&(wk.0, serde_bytes::Bytes::new(&wk.1)))?;
        }
        if let Some(isf) = &self.integrity_scope_flags {
            seq.serialize_element(isf)?;
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for BibSecurityContextParameter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BibSecurityContexParameterVisitor;

        impl<'de> Visitor<'de> for BibSecurityContexParameterVisitor {
            type Value = BibSecurityContextParameter;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte sequence")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let sha_variant = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                // TODO: deal with wrapped key
                let wrapped_key = None;
                let integrity_scope_flags = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                Ok(BibSecurityContextParameter {
                    sha_variant,
                    wrapped_key,
                    integrity_scope_flags,
                })
            }
        }

        deserializer.deserialize_seq(BibSecurityContexParameterVisitor)
    }
}

#[derive(Error, Debug)]
pub enum IntegrityBlockBuilderError {
    #[error("Security Tragets MUST have at least one enrty")]
    MissingSecurityTargets,
    #[error("Security Context Flag set but no context parameter given")]
    FlagSetButNoParameter,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityBlockBuilder {
    security_targets: Option<Vec<u64>>, // array of block numbers TODO:  MUST represent the block number of a block that exists in the bundle
    security_context_id: SecurityContextId,
    security_context_flags: SecurityContextFlag, // bit field
    security_source: EndpointID,
    security_context_parameters: Option<BibSecurityContextParameter>, // optional
    security_results: Vec<Vec<(u64, ByteBuffer)>>, // output of security operations
}

impl IntegrityBlockBuilder {
    pub fn new() -> IntegrityBlockBuilder {
        IntegrityBlockBuilder {
            security_targets: None,
            security_context_id: BIB_HMAC_SHA2_ID,
            security_context_flags: SEC_CONTEXT_ABSENT,
            security_source: EndpointID::none(),
            security_context_parameters: None,
            security_results: Vec::new(),
        }
    }

    pub fn security_targets(mut self, security_targets: Vec<u64>) -> Self {
        self.security_targets = Some(security_targets);
        self
    }
    /*
    pub fn security_context_id(mut self, security_context_id: SecurityContextId) -> Self {
        self.security_context_id = security_context_id;
        self
    }*/
    pub fn security_context_flags(mut self, security_context_flags: SecurityContextFlag) -> Self {
        self.security_context_flags = security_context_flags;
        self
    }
    pub fn security_source(mut self, security_source: EndpointID) -> Self {
        self.security_source = security_source;
        self
    }
    pub fn security_context_parameters(
        mut self,
        security_context_parameters: BibSecurityContextParameter,
    ) -> Self {
        self.security_context_parameters = Some(security_context_parameters);
        self
    }
    pub fn security_results(mut self, security_results: Vec<Vec<(u64, ByteBuffer)>>) -> Self {
        self.security_results = security_results;
        self
    }
    pub fn build(self) -> Result<IntegrityBlock, IntegrityBlockBuilderError> {
        if let Some(security_targets) = self.security_targets {
            if let Some(_security_context_parameters) = self.security_context_parameters.clone() {
                Ok(IntegrityBlock {
                    security_targets,
                    security_context_id: self.security_context_id,
                    security_context_flags: self.security_context_flags,
                    security_source: self.security_source,
                    security_context_parameters: self.security_context_parameters,
                    security_results: self.security_results,
                })
            } else {
                Err(IntegrityBlockBuilderError::FlagSetButNoParameter)
            }
        } else {
            Err(IntegrityBlockBuilderError::MissingSecurityTargets)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityBlock {
    pub security_targets: Vec<u64>, // array of block numbers
    pub security_context_id: SecurityContextId,
    pub security_context_flags: SecurityContextFlag, // bit field
    pub security_source: EndpointID,
    pub security_context_parameters: Option<BibSecurityContextParameter>,
    pub security_results: Vec<Vec<(u64, ByteBuffer)>>, // output of security operations
}

impl IntegrityBlock {
    pub fn new() -> IntegrityBlock {
        IntegrityBlock {
            security_targets: Vec::new(),
            security_context_id: BIB_HMAC_SHA2_ID,
            security_context_flags: SEC_CONTEXT_ABSENT,
            security_source: EndpointID::none(),
            security_context_parameters: None,
            security_results: Vec::new(),
        }
    }
    fn hmac_sha384_compute(&self, key_bytes: &[u8; 16], payload: &ByteBuffer) -> Vec<u8> {
        let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key_bytes)
            .expect("HMAC can take key of any size");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()

        // for testing only
        //
        // let result = mac.finalize();
        // let code_bytes = result.into_bytes();
        // println!("hmac: {:x}", code_bytes);
        // code_bytes.to_vec()
    }

    fn hmac_sha256_compute(&self, key_bytes: &[u8; 16], payload: &ByteBuffer) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key_bytes)
            .expect("HMAC can take key of any size");
        //let mut mac = Hmac::<Sha256>::new_from_slice(key_bytes).expect("HMAC can take key of any size");

        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    fn hmac_sha512_compute(&self, key_bytes: &[u8; 16], payload: &ByteBuffer) -> Vec<u8> {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key_bytes)
            .expect("HMAC can take key of any size");
        //let mut mac = Hmac::<Sha512>::new_from_slice(key_bytes).expect("HMAC can take key of any size");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn compute_hmac(&mut self, key_bytes: [u8; 16], ippt_list: Vec<(u64, &ByteBuffer)>) {
        // match ippt_list values to security targets
        self.security_results = vec![];

        for ippt in ippt_list {
            if self.security_targets.contains(&ippt.0) {
                //let key_bytes = hex!("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b");
                let result_value = match self
                    .security_context_parameters
                    .as_ref()
                    .unwrap()
                    .sha_variant
                    .unwrap()
                    .1
                {
                    5 => self.hmac_sha256_compute(&key_bytes, ippt.1),
                    6 => self.hmac_sha384_compute(&key_bytes, ippt.1),
                    7 => self.hmac_sha512_compute(&key_bytes, ippt.1),
                    _ => panic!("Undefined Sha Variant."),
                };

                // Integrity Security Context BIB-HMAC-SHA2 has only one result field
                // that means for every target there will be only one vector entry
                // with the result id set to 1 and the result value being the
                // outcome of the security operation (-> the MAC)
                // result_id always 1 https://www.rfc-editor.org/rfc/rfc9173.html#name-results
                // +--------------------------+     +---------------------------+
                // |          Target 1        |     |         Target N          |
                // +----------+----+----------+     +---------------------------+
                // | Result 1 |    | Result M | ... | Result 1 |    |  Result K |
                // +----+-----+ .. +----+-----+     +---+------+ .. +----+------+
                // | Id |Value|    | Id |Value|     | Id |Value|    | Id | Value|
                // +----+-----+    +----+-----+     +----+-----+    +----+------+

                self.security_results.push(vec![(ippt.0, result_value)]);
            } else {
                eprint!(
                    "Security Target and Ippt mismatch. Make sure there is an ippt for each target."
                )
            }
        }
    }

    pub fn to_cbor(&self) -> ByteBuffer {
        let mut cbor_format = Vec::<u8>::new();

        cbor_format.append(&mut serde_cbor::to_vec(&self.security_targets).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_id).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_flags).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_source).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_parameters).unwrap());

        // iterate through each target. Create bytes for each signature and onstruct security results format again
        let mut res = Vec::new();
        for i in 0..self.security_targets.len() {
            let next_result = &self.security_results[i];
            let temp_mac = serde_bytes::Bytes::new(&next_result[0].1);
            res.push(vec![(&next_result[0].0, temp_mac)]);
        }
        cbor_format.append(&mut serde_cbor::to_vec(&res).unwrap());
        cbor_format
    }
}

impl Default for IntegrityBlock {
    fn default() -> Self {
        IntegrityBlock::new()
    }
}

impl Default for IntegrityBlockBuilder {
    fn default() -> Self {
        IntegrityBlockBuilder::new()
    }
}

/*
impl Serialize for IntegrityBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = 6;
        println!("in serialize");


        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.security_targets)?;
        seq.serialize_element(&self.security_context_id)?;
        seq.serialize_element(&self.security_context_flags)?;
        seq.serialize_element(&self.security_source)?;
        seq.serialize_element(&self.security_context_parameters)?;
        //seq.serialize_element(&self.security_results)?;
        //let temp = &self.security_results;
        let temp_mac = &serde_bytes::Bytes::new(&self.security_results[0][0].1);

        let test = vec![vec![(1, temp_mac)]];
        seq.serialize_element(&test)?;

        seq.end()
    }
}*/

impl<'de> Deserialize<'de> for IntegrityBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IntegrityBlockVisitor;

        impl<'de> Visitor<'de> for IntegrityBlockVisitor {
            type Value = IntegrityBlock;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte sequence")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let security_targets: Vec<u64> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let security_context_id = seq.next_element()?.unwrap();
                let security_context_flags = seq.next_element()?.unwrap();
                let security_source = seq.next_element()?.unwrap();

                let security_context_parameters = seq.next_element()?.unwrap();

                // TODO: deal with multiple targets
                let results: Vec<Vec<(u64, &[u8])>> = seq.next_element()?.unwrap();
                let mut security_results = Vec::new();

                (0..security_targets.len()).for_each(|i| {
                    let next_result = &results[i];
                    let temp_mac = next_result[0].1.to_vec();
                    security_results.push(vec![(next_result[0].0, temp_mac)]);
                });
                Ok(IntegrityBlock {
                    security_targets,
                    security_context_id,
                    security_context_flags,
                    security_source,
                    security_context_parameters,
                    security_results,
                })
            }
        }

        deserializer.deserialize_seq(IntegrityBlockVisitor)
    }
}

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

// ============================================================================
// Block Confidentiality Block (BCB) Implementation
// https://www.rfc-editor.org/rfc/rfc9172.html#name-block-confidentiality-block
// https://www.rfc-editor.org/rfc/rfc9173.html#name-bcb-aes-gcm
// ============================================================================

/// AAD Scope Flags for BCB
/// https://www.rfc-editor.org/rfc/rfc9173.html#name-aad-scope-flags
pub type AadScopeFlagsType = u16;

bitflags! {
    pub struct AadScopeFlags: AadScopeFlagsType {
        // Include primary block flag
        const AAD_PRIMARY_HEADER = 0x0001;
        // Include target header flag
        const AAD_TARGET_HEADER = 0x0002;
        // Include security header flag
        const AAD_SECURITY_HEADER = 0x0004;
    }
}

pub trait AadValidation {
    fn aad_flags(&self) -> AadScopeFlags;
    fn has_aad_flags(&self, flags: AadScopeFlags) -> bool;
}

impl AadValidation for AadScopeFlagsType {
    fn aad_flags(&self) -> AadScopeFlags {
        AadScopeFlags::from_bits_truncate(*self)
    }
    fn has_aad_flags(&self, flags: AadScopeFlags) -> bool {
        self.aad_flags().contains(flags)
    }
}

/// Additional Authenticated Data (AAD) Builder for BCB
#[derive(Debug, Clone, PartialEq)]
pub struct AadBuilder {
    scope_flags: AadScopeFlagsType,
    primary_block: Option<PrimaryBlock>,
    security_header: Option<SecurityBlockHeader>,
}

impl AadBuilder {
    pub fn new() -> AadBuilder {
        AadBuilder {
            scope_flags: 0x0007, // default: all flags set
            primary_block: None,
            security_header: None,
        }
    }

    pub fn scope_flags(mut self, scope_flags: AadScopeFlagsType) -> Self {
        self.scope_flags = scope_flags;
        self
    }

    pub fn primary_block(mut self, primary_block: PrimaryBlock) -> Self {
        self.primary_block = Some(primary_block);
        self
    }

    pub fn security_header(mut self, security_header: SecurityBlockHeader) -> Self {
        self.security_header = Some(security_header);
        self
    }

    pub fn build(self) -> AdditionalAuthenticatedData {
        AdditionalAuthenticatedData {
            scope_flags: self.scope_flags,
            primary_block: self.primary_block,
            security_header: self.security_header,
        }
    }
}

impl Default for AadBuilder {
    fn default() -> Self {
        AadBuilder::new()
    }
}

/// Additional Authenticated Data (AAD) structure for BCB-AES-GCM
/// https://www.rfc-editor.org/rfc/rfc9173.html#name-scope-2
#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalAuthenticatedData {
    scope_flags: AadScopeFlagsType,
    primary_block: Option<PrimaryBlock>,
    security_header: Option<SecurityBlockHeader>,
}

impl AdditionalAuthenticatedData {
    pub fn new() -> AdditionalAuthenticatedData {
        AdditionalAuthenticatedData {
            scope_flags: 0x0007,
            primary_block: None,
            security_header: None,
        }
    }

    pub fn create(&mut self, target_block: &CanonicalBlock) -> ByteBuffer {
        let mut aad = Vec::<u8>::new();

        // Add scope flags
        aad.append(
            &mut serde_cbor::to_vec(&self.scope_flags)
                .expect("Error creating canonical form of scope flags"),
        );

        // Add primary block if flag is set
        if self.scope_flags.has_aad_flags(AadScopeFlags::AAD_PRIMARY_HEADER) {
            if let Some(pb) = &self.primary_block {
                aad.append(
                    &mut serde_cbor::to_vec(pb)
                        .expect("Error creating canonical form of primary block"),
                );
            } else {
                eprintln!("Primary header flag set but no primary header given!");
            }
        }

        // Add target header if flag is set
        if self.scope_flags.has_aad_flags(AadScopeFlags::AAD_TARGET_HEADER) {
            aad.append(
                &mut self
                    .construct_target_header(target_block)
                    .expect("Error constructing target header"),
            );
        }

        // Add security header if flag is set
        if self.scope_flags.has_aad_flags(AadScopeFlags::AAD_SECURITY_HEADER) {
            if let Some(sh) = &self.security_header {
                aad.append(
                    &mut self
                        .construct_security_header(sh)
                        .expect("Error constructing security header"),
                );
            } else {
                eprintln!("Security header flag set but no security header given!");
            }
        }

        aad
    }

    fn construct_target_header(
        &self,
        target_block: &CanonicalBlock,
    ) -> Result<ByteBuffer, serde_cbor::Error> {
        let mut header = Vec::<u8>::new();
        header.append(&mut serde_cbor::to_vec(&target_block.block_type)?);
        header.append(&mut serde_cbor::to_vec(&target_block.block_number)?);
        header.append(&mut serde_cbor::to_vec(&target_block.block_control_flags)?);
        Ok(header)
    }

    fn construct_security_header(
        &self,
        security_block_parameter: &SecurityBlockHeader,
    ) -> Result<ByteBuffer, serde_cbor::Error> {
        let mut header = Vec::<u8>::new();
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.0)?);
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.1)?);
        header.append(&mut serde_cbor::to_vec(&security_block_parameter.2)?);
        Ok(header)
    }
}

impl Default for AdditionalAuthenticatedData {
    fn default() -> Self {
        AdditionalAuthenticatedData::new()
    }
}

/// BCB Security Context Parameters
/// https://www.rfc-editor.org/rfc/rfc9173.html#name-bcb-aes-gcm-security-contex
#[derive(Debug, Clone, PartialEq)]
pub struct BcbSecurityContextParameter {
    pub aes_variant: Option<(u8, AesVariantType)>,          // Param ID 1
    pub wrapped_key: Option<(u8, Vec<u8>)>,                 // Param ID 2 (TODO: implement key wrapping)
    pub aad_scope_flags: Option<(u8, AadScopeFlagsType)>,   // Param ID 4
}

impl BcbSecurityContextParameter {
    pub fn new(
        aes_variant: Option<(u8, AesVariantType)>,
        wrapped_key: Option<(u8, Vec<u8>)>,
        aad_scope_flags: Option<(u8, AadScopeFlagsType)>,
    ) -> Self {
        Self {
            aes_variant,
            wrapped_key,
            aad_scope_flags,
        }
    }
}

impl Default for BcbSecurityContextParameter {
    fn default() -> Self {
        BcbSecurityContextParameter {
            aes_variant: Some((1, AES_256_GCM)), // Default to AES-256-GCM
            wrapped_key: None,
            aad_scope_flags: Some((4, 0x0007)), // Default: all AAD flags set
        }
    }
}

impl Serialize for BcbSecurityContextParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut num_elems = 0;
        if self.aes_variant.is_some() {
            num_elems += 1;
        }
        if self.wrapped_key.is_some() {
            num_elems += 1;
        }
        if self.aad_scope_flags.is_some() {
            num_elems += 1;
        }

        let mut seq = serializer.serialize_seq(Some(num_elems))?;

        if let Some(av) = &self.aes_variant {
            seq.serialize_element(av)?;
        }
        if let Some(wk) = &self.wrapped_key {
            seq.serialize_element(&(wk.0, serde_bytes::Bytes::new(&wk.1)))?;
        }
        if let Some(aad) = &self.aad_scope_flags {
            seq.serialize_element(aad)?;
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for BcbSecurityContextParameter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BcbSecurityContextParameterVisitor;

        impl<'de> Visitor<'de> for BcbSecurityContextParameterVisitor {
            type Value = BcbSecurityContextParameter;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a BCB security context parameter sequence")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let aes_variant = seq.next_element()?;
                let wrapped_key = None; // TODO: implement wrapped key deserialization
                let aad_scope_flags = seq.next_element()?;

                Ok(BcbSecurityContextParameter {
                    aes_variant,
                    wrapped_key,
                    aad_scope_flags,
                })
            }
        }

        deserializer.deserialize_seq(BcbSecurityContextParameterVisitor)
    }
}

#[derive(Error, Debug)]
pub enum ConfidentialityBlockBuilderError {
    #[error("Security Targets MUST have at least one entry")]
    MissingSecurityTargets,
    #[error("Security Context Flag set but no context parameter given")]
    FlagSetButNoParameter,
}

/// Confidentiality Block Builder
#[derive(Debug, Clone, PartialEq)]
pub struct ConfidentialityBlockBuilder {
    security_targets: Option<Vec<u64>>,
    security_context_id: SecurityContextId,
    security_context_flags: SecurityContextFlag,
    security_source: EndpointID,
    security_context_parameters: Option<BcbSecurityContextParameter>,
    security_results: Vec<Vec<(u64, ByteBuffer)>>,
}

impl ConfidentialityBlockBuilder {
    pub fn new() -> ConfidentialityBlockBuilder {
        ConfidentialityBlockBuilder {
            security_targets: None,
            security_context_id: BCB_AES_GCM_ID,
            security_context_flags: SEC_CONTEXT_ABSENT,
            security_source: EndpointID::none(),
            security_context_parameters: None,
            security_results: Vec::new(),
        }
    }

    pub fn security_targets(mut self, security_targets: Vec<u64>) -> Self {
        self.security_targets = Some(security_targets);
        self
    }

    pub fn security_context_flags(mut self, security_context_flags: SecurityContextFlag) -> Self {
        self.security_context_flags = security_context_flags;
        self
    }

    pub fn security_source(mut self, security_source: EndpointID) -> Self {
        self.security_source = security_source;
        self
    }

    pub fn security_context_parameters(
        mut self,
        security_context_parameters: BcbSecurityContextParameter,
    ) -> Self {
        self.security_context_parameters = Some(security_context_parameters);
        self
    }

    pub fn security_results(mut self, security_results: Vec<Vec<(u64, ByteBuffer)>>) -> Self {
        self.security_results = security_results;
        self
    }

    pub fn build(self) -> Result<ConfidentialityBlock, ConfidentialityBlockBuilderError> {
        if let Some(security_targets) = self.security_targets {
            if self.security_context_flags == SEC_CONTEXT_PRESENT
                && self.security_context_parameters.is_none()
            {
                return Err(ConfidentialityBlockBuilderError::FlagSetButNoParameter);
            }
            Ok(ConfidentialityBlock {
                security_targets,
                security_context_id: self.security_context_id,
                security_context_flags: self.security_context_flags,
                security_source: self.security_source,
                security_context_parameters: self.security_context_parameters,
                security_results: self.security_results,
            })
        } else {
            Err(ConfidentialityBlockBuilderError::MissingSecurityTargets)
        }
    }
}

impl Default for ConfidentialityBlockBuilder {
    fn default() -> Self {
        ConfidentialityBlockBuilder::new()
    }
}

/// Block Confidentiality Block (BCB)
/// https://www.rfc-editor.org/rfc/rfc9172.html#name-block-confidentiality-block
#[derive(Debug, Clone, PartialEq)]
pub struct ConfidentialityBlock {
    pub security_targets: Vec<u64>,
    pub security_context_id: SecurityContextId,
    pub security_context_flags: SecurityContextFlag,
    pub security_source: EndpointID,
    pub security_context_parameters: Option<BcbSecurityContextParameter>,
    pub security_results: Vec<Vec<(u64, ByteBuffer)>>, // Results include IV and auth tag
}

impl ConfidentialityBlock {
    pub fn new() -> ConfidentialityBlock {
        ConfidentialityBlock {
            security_targets: Vec::new(),
            security_context_id: BCB_AES_GCM_ID,
            security_context_flags: SEC_CONTEXT_ABSENT,
            security_source: EndpointID::none(),
            security_context_parameters: None,
            security_results: Vec::new(),
        }
    }

    /// Encrypt data using AES-128-GCM
    fn aes_128_gcm_encrypt(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
        let cipher = Aes128Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher.encrypt(nonce, payload)?;

        // AES-GCM produces: ciphertext || authentication_tag (last 16 bytes)
        let tag_start = ciphertext.len().saturating_sub(16);
        let auth_tag = ciphertext[tag_start..].to_vec();
        let ciphertext_only = ciphertext[..tag_start].to_vec();

        Ok((ciphertext_only, auth_tag))
    }

    /// Encrypt data using AES-256-GCM
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher.encrypt(nonce, payload)?;

        // AES-GCM produces: ciphertext || authentication_tag (last 16 bytes)
        let tag_start = ciphertext.len().saturating_sub(16);
        let auth_tag = ciphertext[tag_start..].to_vec();
        let ciphertext_only = ciphertext[..tag_start].to_vec();

        Ok((ciphertext_only, auth_tag))
    }

    /// Decrypt data using AES-128-GCM
    fn aes_128_gcm_decrypt(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        ciphertext: &[u8],
        auth_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes128Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        // Reconstruct full ciphertext with tag
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(auth_tag);

        let payload = Payload {
            msg: &full_ciphertext,
            aad,
        };

        cipher.decrypt(nonce, payload)
    }

    /// Decrypt data using AES-256-GCM
    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
        ciphertext: &[u8],
        auth_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        // Reconstruct full ciphertext with tag
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(auth_tag);

        let payload = Payload {
            msg: &full_ciphertext,
            aad,
        };

        cipher.decrypt(nonce, payload)
    }

    /// Encrypt target blocks with AES-GCM
    /// Returns list of (target_number, iv, auth_tag, ciphertext) for each target
    pub fn encrypt_targets(
        &mut self,
        key_bytes: &[u8],
        iv_list: Vec<(u64, [u8; 12])>, // (target_number, iv)
        aad_list: Vec<(u64, &ByteBuffer)>, // (target_number, aad)
        plaintext_list: Vec<(u64, &ByteBuffer)>, // (target_number, plaintext)
    ) -> Result<(), String> {
        self.security_results = vec![];

        let aes_variant = self
            .security_context_parameters
            .as_ref()
            .and_then(|p| p.aes_variant)
            .unwrap_or((1, AES_256_GCM))
            .1;

        for (target_num, plaintext) in plaintext_list {
            if !self.security_targets.contains(&target_num) {
                return Err(format!(
                    "Target {} not in security targets list",
                    target_num
                ));
            }

            // Find matching IV and AAD
            let iv = iv_list
                .iter()
                .find(|(n, _)| *n == target_num)
                .ok_or_else(|| format!("No IV found for target {}", target_num))?
                .1;

            let aad = aad_list
                .iter()
                .find(|(n, _)| *n == target_num)
                .ok_or_else(|| format!("No AAD found for target {}", target_num))?
                .1;

            let (_ciphertext, auth_tag) = match aes_variant {
                AES_128_GCM => {
                    if key_bytes.len() != 16 {
                        return Err("AES-128-GCM requires 16-byte key".to_string());
                    }
                    let key: [u8; 16] = key_bytes.try_into().unwrap();
                    self.aes_128_gcm_encrypt(&key, &iv, plaintext, aad)
                        .map_err(|e| format!("AES-128-GCM encryption failed: {:?}", e))?
                }
                AES_256_GCM => {
                    if key_bytes.len() != 32 {
                        return Err("AES-256-GCM requires 32-byte key".to_string());
                    }
                    let key: [u8; 32] = key_bytes.try_into().unwrap();
                    self.aes_256_gcm_encrypt(&key, &iv, plaintext, aad)
                        .map_err(|e| format!("AES-256-GCM encryption failed: {:?}", e))?
                }
                _ => return Err(format!("Unsupported AES variant: {}", aes_variant)),
            };

            // BCB-AES-GCM Security Results:
            // Result ID 1: Authentication Tag
            // Result ID 2: IV (Initialization Vector)
            // Note: The ciphertext replaces the plaintext in-place in the target block
            self.security_results.push(vec![
                (1, auth_tag),
                (2, iv.to_vec()),
            ]);
        }

        Ok(())
    }

    /// Decrypt target blocks with AES-GCM
    pub fn decrypt_targets(
        &self,
        key_bytes: &[u8],
        aad_list: Vec<(u64, &ByteBuffer)>, // (target_number, aad)
        ciphertext_list: Vec<(u64, &ByteBuffer)>, // (target_number, ciphertext)
    ) -> Result<Vec<(u64, ByteBuffer)>, String> {
        let aes_variant = self
            .security_context_parameters
            .as_ref()
            .and_then(|p| p.aes_variant)
            .unwrap_or((1, AES_256_GCM))
            .1;

        let mut plaintexts = Vec::new();

        for (i, target_num) in self.security_targets.iter().enumerate() {
            if i >= self.security_results.len() {
                return Err(format!("No security results for target {}", target_num));
            }

            let results = &self.security_results[i];

            // Extract auth tag (result ID 1) and IV (result ID 2)
            let auth_tag = results
                .iter()
                .find(|(id, _)| *id == 1)
                .ok_or_else(|| format!("No auth tag found for target {}", target_num))?
                .1
                .as_slice();

            let iv_bytes = results
                .iter()
                .find(|(id, _)| *id == 2)
                .ok_or_else(|| format!("No IV found for target {}", target_num))?
                .1
                .as_slice();

            if iv_bytes.len() != 12 {
                return Err(format!("Invalid IV length for target {}", target_num));
            }
            let iv: [u8; 12] = iv_bytes.try_into().unwrap();

            let ciphertext = ciphertext_list
                .iter()
                .find(|(n, _)| n == target_num)
                .ok_or_else(|| format!("No ciphertext found for target {}", target_num))?
                .1;

            let aad = aad_list
                .iter()
                .find(|(n, _)| n == target_num)
                .ok_or_else(|| format!("No AAD found for target {}", target_num))?
                .1;

            let plaintext = match aes_variant {
                AES_128_GCM => {
                    if key_bytes.len() != 16 {
                        return Err("AES-128-GCM requires 16-byte key".to_string());
                    }
                    let key: [u8; 16] = key_bytes.try_into().unwrap();
                    self.aes_128_gcm_decrypt(&key, &iv, ciphertext, auth_tag, aad)
                        .map_err(|e| format!("AES-128-GCM decryption failed: {:?}", e))?
                }
                AES_256_GCM => {
                    if key_bytes.len() != 32 {
                        return Err("AES-256-GCM requires 32-byte key".to_string());
                    }
                    let key: [u8; 32] = key_bytes.try_into().unwrap();
                    self.aes_256_gcm_decrypt(&key, &iv, ciphertext, auth_tag, aad)
                        .map_err(|e| format!("AES-256-GCM decryption failed: {:?}", e))?
                }
                _ => return Err(format!("Unsupported AES variant: {}", aes_variant)),
            };

            plaintexts.push((*target_num, plaintext));
        }

        Ok(plaintexts)
    }

    pub fn to_cbor(&self) -> ByteBuffer {
        let mut cbor_format = Vec::<u8>::new();

        cbor_format.append(&mut serde_cbor::to_vec(&self.security_targets).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_id).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_flags).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_source).unwrap());
        cbor_format.append(&mut serde_cbor::to_vec(&self.security_context_parameters).unwrap());

        // Serialize security results
        let mut res = Vec::new();
        for i in 0..self.security_targets.len() {
            let next_result = &self.security_results[i];
            let mut result_vec = Vec::new();
            for (result_id, result_value) in next_result {
                let temp_bytes = serde_bytes::Bytes::new(result_value);
                result_vec.push((result_id, temp_bytes));
            }
            res.push(result_vec);
        }
        cbor_format.append(&mut serde_cbor::to_vec(&res).unwrap());
        cbor_format
    }
}

impl Default for ConfidentialityBlock {
    fn default() -> Self {
        ConfidentialityBlock::new()
    }
}

impl<'de> Deserialize<'de> for ConfidentialityBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConfidentialityBlockVisitor;

        impl<'de> Visitor<'de> for ConfidentialityBlockVisitor {
            type Value = ConfidentialityBlock;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a confidentiality block sequence")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let security_targets: Vec<u64> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let security_context_id = seq.next_element()?.unwrap();
                let security_context_flags = seq.next_element()?.unwrap();
                let security_source = seq.next_element()?.unwrap();
                let security_context_parameters = seq.next_element()?.unwrap();

                // Deserialize security results
                let results: Vec<Vec<(u64, &[u8])>> = seq.next_element()?.unwrap();
                let mut security_results = Vec::new();

                for target_results in results {
                    let mut result_vec = Vec::new();
                    for (result_id, result_value) in target_results {
                        result_vec.push((result_id, result_value.to_vec()));
                    }
                    security_results.push(result_vec);
                }

                Ok(ConfidentialityBlock {
                    security_targets,
                    security_context_id,
                    security_context_flags,
                    security_source,
                    security_context_parameters,
                    security_results,
                })
            }
        }

        deserializer.deserialize_seq(ConfidentialityBlockVisitor)
    }
}

pub fn new_confidentiality_block(
    block_number: u64,
    bcf: BlockControlFlags,
    security_block: ByteBuffer,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(CONFIDENTIALITY_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf.bits())
        .data(CanonicalData::Unknown(security_block))
        .build()
        .unwrap()
}
