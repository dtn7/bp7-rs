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

    /// Create the IPPT of a security target block, omitting the primary block or the
    /// security header if indicated by the scope flags but not given
    pub fn create(&mut self, target_block: &CanonicalBlock) -> ByteBuffer {
        self.security_target_contents = canonical_target_contents(IpptTarget::Block(target_block));
        ippt(
            self.scope_flags,
            self.primary_block.as_ref(),
            IpptTarget::Block(target_block),
            self.security_header,
        )
    }
}

/// Security target of a BIB, the primary block or another block of the bundle
#[derive(Debug, Clone, Copy)]
pub enum IpptTarget<'a> {
    PrimaryBlock(&'a PrimaryBlock),
    Block(&'a CanonicalBlock),
}

/// Integrity protected plaintext of a security target (RFC 9173 3.7)
///
/// If the security target is the primary block, the primary block and target header are
/// not included separately, regardless of the scope flags.
pub fn integrity_protected_plaintext(
    scope_flags: IntegrityScopeFlagsType,
    primary_block: &PrimaryBlock,
    target: IpptTarget,
    security_header: SecurityBlockHeader,
) -> ByteBuffer {
    ippt(
        scope_flags,
        Some(primary_block),
        target,
        Some(security_header),
    )
}

fn ippt(
    scope_flags: IntegrityScopeFlagsType,
    primary_block: Option<&PrimaryBlock>,
    target: IpptTarget,
    security_header: Option<SecurityBlockHeader>,
) -> ByteBuffer {
    let encode_error = "Error encoding integrity protected plaintext";
    let flags = IntegrityScopeFlags::from_bits_truncate(scope_flags);
    // the scope flags are always included, with reserved and unassigned bits set to 0
    let mut ippt = serde_cbor::to_vec(&flags.bits()).expect(encode_error);
    if let IpptTarget::Block(block) = target {
        if flags.contains(IntegrityScopeFlags::INTEGRITY_PRIMARY_HEADER)
            && let Some(primary_block) = primary_block
        {
            serde_cbor::to_writer(&mut ippt, primary_block).expect(encode_error);
        }
        if flags.contains(IntegrityScopeFlags::INTEGRITY_PAYLOAD_HEADER) {
            serde_cbor::to_writer(&mut ippt, &block.block_type).expect(encode_error);
            serde_cbor::to_writer(&mut ippt, &block.block_number).expect(encode_error);
            serde_cbor::to_writer(&mut ippt, &block.block_control_flags).expect(encode_error);
        }
    }
    if flags.contains(IntegrityScopeFlags::INTEGRITY_SECURITY_HEADER)
        && let Some((block_type, block_number, block_flags)) = security_header
    {
        serde_cbor::to_writer(&mut ippt, &block_type).expect(encode_error);
        serde_cbor::to_writer(&mut ippt, &block_number).expect(encode_error);
        serde_cbor::to_writer(&mut ippt, &block_flags).expect(encode_error);
    }
    ippt.extend(canonical_target_contents(target));
    ippt
}

/// Canonical form of a security target, the primary block or the block-type-specific
/// data of a block, as CBOR byte string
fn canonical_target_contents(target: IpptTarget) -> ByteBuffer {
    let encode_error = "Error encoding security target";
    let contents = match target {
        IpptTarget::PrimaryBlock(primary_block) => {
            serde_cbor::to_vec(primary_block).expect(encode_error)
        }
        IpptTarget::Block(block) => match block.data() {
            CanonicalData::Data(data) | CanonicalData::Unknown(data) => data.clone(),
            other => other.to_cbor(),
        },
    };
    serde_cbor::to_vec(&serde_bytes::Bytes::new(&contents)).expect(encode_error)
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

/// SHA variant of a BIB, HMAC-SHA-384 if none is given (RFC 9173 3.3.1), and the HMAC key,
/// unwrapped with the given key if the BIB has a wrapped key
fn sha_variant_and_key(
    bib: &IntegrityBlock,
    key: &[u8],
) -> Result<(ShaVariantType, ByteBuffer), BpsecError> {
    let params: BibSecurityContextParameter = bib
        .parameters()?
        .unwrap_or(BibSecurityContextParameter::new(None, None, None));
    let variant = params.sha_variant.map_or(HMAC_SHA_384, |v| v.1);
    let key = super::operation_key(key, params.wrapped_key.as_ref().map(|(_, k)| k.as_slice()))?;
    Ok((variant, key))
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
/// result id 1 (RFC 9173 3.4). If the BIB has a wrapped key, `key` is the key encryption
/// key to unwrap the HMAC key.
pub fn compute_hmac(
    bib: &mut IntegrityBlock,
    key: &[u8],
    ippt_list: &[(u64, &ByteBuffer)],
) -> Result<(), BpsecError> {
    let (variant, key) = sha_variant_and_key(bib, key)?;
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
        let expected = compute_expected_hmac(variant, &key, ippt)?;
        results.push(vec![(EXPECTED_HMAC_RESULT, Value::Bytes(expected))]);
    }
    bib.security_results = results;
    Ok(())
}

/// Verify the expected HMAC of every security target of a BIB, given the IPPT of each
/// target as pairs of target block number and IPPT. If the BIB has a wrapped key, `key`
/// is the key encryption key to unwrap the HMAC key.
pub fn verify_hmac(
    bib: &IntegrityBlock,
    key: &[u8],
    ippt_list: &[(u64, &ByteBuffer)],
) -> Result<bool, BpsecError> {
    let (variant, key) = sha_variant_and_key(bib, key)?;
    for target in &bib.security_targets {
        let (_, ippt) = ippt_list
            .iter()
            .find(|(t, _)| t == target)
            .ok_or(BpsecError::MissingTargetInput(*target))?;
        let Some(Value::Bytes(received)) = bib.result(*target, EXPECTED_HMAC_RESULT) else {
            return Ok(false);
        };
        if !verify_expected_hmac(variant, &key, ippt, received)? {
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
