//! BIB-HMAC-SHA2 security context ([RFC 9173 3](https://www.rfc-editor.org/rfc/rfc9173.html#name-security-context-bib-hmac-s))

use std::fmt;

use bitflags::bitflags;
use hmac::{Hmac, Mac};
use serde::de::{SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_cbor::Value;
use sha2::{Sha256, Sha384, Sha512};

use crate::bpsec::*;
use crate::bundle::ByteBuffer;
use crate::canonical::{CanonicalBlock, CanonicalData};
use crate::primary::PrimaryBlock;

// SHA Variant
// https://www.rfc-editor.org/rfc/rfc9173.html#name-sha-variant
pub type ShaVariantType = u16;
pub const HMAC_SHA_256: ShaVariantType = 5;
pub const HMAC_SHA_384: ShaVariantType = 6; // default
pub const HMAC_SHA_512: ShaVariantType = 7;

// Security context parameter ids (RFC 9173 3.3)
pub const SHA_VARIANT_PARAMETER: u64 = 1;
pub const WRAPPED_KEY_PARAMETER: u64 = 2;
pub const INTEGRITY_SCOPE_FLAGS_PARAMETER: u64 = 3;

// Security result id of the expected HMAC (RFC 9173 3.4)
pub const EXPECTED_HMAC_RESULT: u64 = 1;

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
            .contains(IntegrityScopeFlags::INTEGRITY_PRIMARY_HEADER)
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
            .contains(IntegrityScopeFlags::INTEGRITY_PAYLOAD_HEADER)
        {
            optional_ippt_data.append(
                self.construct_payload_header(payload_block)
                    .expect("Error constructing payload header")
                    .as_mut(),
            );
        }
        if self
            .scope_flags
            .contains(IntegrityScopeFlags::INTEGRITY_SECURITY_HEADER)
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
    fn flags(&self) -> IntegrityScopeFlags;
    fn contains(&self, flags: IntegrityScopeFlags) -> bool;
}
impl ScopeValidation for IntegrityScopeFlagsType {
    fn flags(&self) -> IntegrityScopeFlags {
        IntegrityScopeFlags::from_bits_truncate(*self)
    }
    fn contains(&self, flags: IntegrityScopeFlags) -> bool
    where
        Self: Sized,
    {
        self.flags().contains(flags)
    }
}

// Security Context Parameters
// https://www.rfc-editor.org/rfc/rfc9173.html#name-enumerations
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

impl SecurityContextParameters for BibSecurityContextParameter {
    fn to_parameters(&self) -> Vec<SecurityParameter> {
        let mut params = Vec::new();
        if let Some((id, variant)) = self.sha_variant {
            params.push((id.into(), Value::Integer(variant.into())));
        }
        if let Some((id, key)) = &self.wrapped_key {
            params.push(((*id).into(), Value::Bytes(key.clone())));
        }
        if let Some((id, flags)) = self.integrity_scope_flags {
            params.push((id.into(), Value::Integer(flags.into())));
        }
        params
    }

    // all parameters are optional and identified by their id (RFC 9173 3.3.4)
    fn from_parameters(parameters: &[SecurityParameter]) -> Result<Self, BpsecError> {
        let mut result = BibSecurityContextParameter::new(None, None, None);
        for (id, value) in parameters {
            let invalid = || BpsecError::InvalidParameter(*id);
            match (*id, value) {
                (SHA_VARIANT_PARAMETER, Value::Integer(v)) => {
                    let variant = ShaVariantType::try_from(*v).map_err(|_| invalid())?;
                    result.sha_variant = Some((*id as u8, variant));
                }
                (WRAPPED_KEY_PARAMETER, Value::Bytes(key)) => {
                    result.wrapped_key = Some((*id as u8, key.clone()));
                }
                (INTEGRITY_SCOPE_FLAGS_PARAMETER, Value::Integer(v)) => {
                    let flags = IntegrityScopeFlagsType::try_from(*v).map_err(|_| invalid())?;
                    result.integrity_scope_flags = Some((*id as u8, flags));
                }
                (SHA_VARIANT_PARAMETER..=INTEGRITY_SCOPE_FLAGS_PARAMETER, _) => {
                    return Err(invalid());
                }
                _ => return Err(BpsecError::UnknownParameter(*id)),
            }
        }
        Ok(result)
    }
}

// encoded as the security context parameters array of an abstract security block
impl Serialize for BibSecurityContextParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_parameters().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BibSecurityContextParameter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ParametersVisitor;

        impl<'de> Visitor<'de> for ParametersVisitor {
            type Value = Vec<SecurityParameter>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("security context parameters")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut params = Vec::new();
                while let Some(param) = seq.next_element()? {
                    params.push(param);
                }
                Ok(params)
            }
        }

        let params = deserializer.deserialize_seq(ParametersVisitor)?;
        BibSecurityContextParameter::from_parameters(&params).map_err(de::Error::custom)
    }
}

fn new_mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], ippt: &[u8]) -> M {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(ippt);
    mac
}

/// SHA variant of a BIB, HMAC-SHA-384 if none is given (RFC 9173 3.3.1)
fn sha_variant(bib: &IntegrityBlock) -> Result<ShaVariantType, BpsecError> {
    let params: Option<BibSecurityContextParameter> = bib.parameters()?;
    Ok(params
        .and_then(|p| p.sha_variant)
        .map_or(HMAC_SHA_384, |v| v.1))
}

fn compute_expected_hmac(
    variant: ShaVariantType,
    key: &[u8],
    ippt: &[u8],
) -> Result<Vec<u8>, BpsecError> {
    let hmac = match variant {
        HMAC_SHA_256 => new_mac::<Hmac<Sha256>>(key, ippt)
            .finalize()
            .into_bytes()
            .to_vec(),
        HMAC_SHA_384 => new_mac::<Hmac<Sha384>>(key, ippt)
            .finalize()
            .into_bytes()
            .to_vec(),
        HMAC_SHA_512 => new_mac::<Hmac<Sha512>>(key, ippt)
            .finalize()
            .into_bytes()
            .to_vec(),
        _ => return Err(BpsecError::Unsupported(format!("sha variant {}", variant))),
    };
    Ok(hmac)
}

/// Compare a received HMAC in constant time
fn verify_expected_hmac(
    variant: ShaVariantType,
    key: &[u8],
    ippt: &[u8],
    received: &[u8],
) -> Result<bool, BpsecError> {
    let valid = match variant {
        HMAC_SHA_256 => new_mac::<Hmac<Sha256>>(key, ippt).verify_slice(received),
        HMAC_SHA_384 => new_mac::<Hmac<Sha384>>(key, ippt).verify_slice(received),
        HMAC_SHA_512 => new_mac::<Hmac<Sha512>>(key, ippt).verify_slice(received),
        _ => return Err(BpsecError::Unsupported(format!("sha variant {}", variant))),
    };
    Ok(valid.is_ok())
}

/// Compute the expected HMAC of every security target of a BIB from the IPPT of each
/// target, given as pairs of target block number and IPPT, and set them as results.
///
/// The BIB-HMAC-SHA2 context has a single result per target, the expected HMAC with
/// result id 1 (RFC 9173 3.4).
pub fn compute_hmac(
    bib: &mut IntegrityBlock,
    key: &[u8],
    ippt_list: &[(u64, &ByteBuffer)],
) -> Result<(), BpsecError> {
    let variant = sha_variant(bib)?;
    if let Some((target, _)) = ippt_list
        .iter()
        .find(|(target, _)| !bib.security_targets.contains(target))
    {
        return Err(BpsecError::UnknownTarget(*target));
    }
    // results are in the order of the security targets (RFC 9172 3.6)
    let mut results = Vec::with_capacity(bib.security_targets.len());
    for target in &bib.security_targets {
        let (_, ippt) = ippt_list
            .iter()
            .find(|(t, _)| t == target)
            .ok_or(BpsecError::MissingTargetInput(*target))?;
        let expected = compute_expected_hmac(variant, key, ippt)?;
        results.push(vec![(EXPECTED_HMAC_RESULT, Value::Bytes(expected))]);
    }
    bib.security_results = results;
    Ok(())
}

/// Verify the expected HMAC of every security target of a BIB, given the IPPT of each
/// target as pairs of target block number and IPPT.
pub fn verify_hmac(
    bib: &IntegrityBlock,
    key: &[u8],
    ippt_list: &[(u64, &ByteBuffer)],
) -> Result<bool, BpsecError> {
    let variant = sha_variant(bib)?;
    for target in &bib.security_targets {
        let (_, ippt) = ippt_list
            .iter()
            .find(|(t, _)| t == target)
            .ok_or(BpsecError::MissingTargetInput(*target))?;
        let Some(Value::Bytes(received)) = bib.result(*target, EXPECTED_HMAC_RESULT) else {
            return Ok(false);
        };
        if !verify_expected_hmac(variant, key, ippt, received)? {
            return Ok(false);
        }
    }
    Ok(true)
}

impl IntegrityBlock {
    /// Compute the BIB-HMAC-SHA2 results, see [`compute_hmac`]
    pub fn compute_hmac(
        &mut self,
        key: impl AsRef<[u8]>,
        ippt_list: Vec<(u64, &ByteBuffer)>,
    ) -> Result<(), BpsecError> {
        compute_hmac(self, key.as_ref(), &ippt_list)
    }
}
