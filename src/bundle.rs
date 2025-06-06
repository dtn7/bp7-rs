use core::cmp;
use core::convert::TryFrom;
use core::fmt;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};

use super::canonical::*;
use super::crc::*;
use super::dtntime::*;
use super::eid::*;
use super::flags::*;
use super::primary::*;
use crate::error::{Error, ErrorList};
use thiserror::Error;

/// Version for upcoming bundle protocol standard is 7.
pub const DTN_VERSION: u32 = 7;

pub type ByteBuffer = Vec<u8>;

pub type DtnVersionType = u32;
pub type CanonicalBlockNumberType = u64;
pub type FragOffsetType = u64;
pub type TotalDataLengthType = u64;

/******************************
 *
 * Block
 *
 ******************************/

pub trait Block {
    /// Convert block struct to a serializable enum
    fn to_cbor(&self) -> ByteBuffer;
}

/******************************
 *
 * Bundle
 *
 ******************************/

#[derive(Error, Debug)]
pub enum BundleBuilderError {
    #[error("Missing payload block")]
    NoPayloadBlock,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct BundleBuilder {
    primary: PrimaryBlock,
    canonicals: Vec<CanonicalBlock>,
}

impl BundleBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn primary(mut self, primary: PrimaryBlock) -> Self {
        self.primary = primary;
        self
    }
    pub fn canonicals(mut self, canonicals: Vec<CanonicalBlock>) -> Self {
        self.canonicals = canonicals;
        self
    }
    pub fn payload(mut self, payload: ByteBuffer) -> Self {
        let payload = crate::canonical::new_payload_block(BlockControlFlags::empty(), payload);
        self.canonicals.push(payload);
        self
    }
    pub fn build(mut self) -> Result<Bundle, BundleBuilderError> {
        self.canonicals
            .sort_by(|a, b| b.block_number.cmp(&a.block_number));

        if self.canonicals.is_empty() || self.canonicals.last().unwrap().payload_data().is_none() {
            Err(BundleBuilderError::NoPayloadBlock)
        } else {
            Ok(Bundle {
                primary: self.primary,
                canonicals: self.canonicals,
            })
        }
    }
}

/// Bundle represents a bundle as defined in section 4.2.1. Each Bundle contains
/// one primary block and multiple canonical blocks.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Bundle {
    pub primary: PrimaryBlock,
    pub canonicals: Vec<CanonicalBlock>,
}

impl Serialize for Bundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.canonicals.len() + 1))?;
        seq.serialize_element(&self.primary)?;
        for e in &self.canonicals {
            seq.serialize_element(&e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Bundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BundleVisitor;

        impl<'de> Visitor<'de> for BundleVisitor {
            type Value = Bundle;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bundle")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let primary: PrimaryBlock = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let mut canonicals: Vec<CanonicalBlock> = Vec::new();
                while let Some(next) = seq.next_element::<CanonicalBlock>()? {
                    canonicals.push(next);
                }

                Ok(Bundle {
                    primary,
                    canonicals,
                })
            }
        }

        deserializer.deserialize_any(BundleVisitor)
    }
}

impl Bundle {
    pub fn new(primary: PrimaryBlock, canonicals: Vec<CanonicalBlock>) -> Bundle {
        Bundle {
            primary,
            canonicals,
        }
    }

    /// Validate bundle and optionally return list of errors.
    pub fn validate(&self) -> Result<(), ErrorList> {
        let mut errors: ErrorList = Vec::new();
        //let mut block_numbers: Vec<CanonicalBlockNumberType> = Vec::new();
        //let mut block_types: Vec<CanonicalBlockType> = Vec::new();

        let mut b_num: std::collections::HashSet<u64> =
            std::collections::HashSet::with_capacity(15);
        let mut b_types: std::collections::HashSet<u64> =
            std::collections::HashSet::with_capacity(15);

        if let Err(mut err) = self.primary.validate() {
            errors.append(&mut err);
        }
        for blck in &self.canonicals {
            if let Err(mut err) = blck.validate() {
                errors.append(&mut err);
            }
            if (self
                .primary
                .bundle_control_flags
                .contains(BundleControlFlags::BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD)
                || self.primary.source == EndpointID::none())
                && blck
                    .block_control_flags
                    .flags()
                    .contains(BlockControlFlags::BLOCK_STATUS_REPORT)
            {
                errors.push(Error::BundleError(
                        "Bundle Processing Control Flags indicate that this bundle's payload is an administrative record or the source node is omitted, but the \"Transmit status report if block cannot be processed\" Block Processing Control Flag was set in a Canonical Block".to_string()
                    ));
            }
            if !b_num.insert(blck.block_number) {
                errors.push(Error::BundleError(
                    "Block numbers occurred multiple times".to_string(),
                ));
            }
            if !b_types.insert(blck.block_type)
                && (blck.block_type == BUNDLE_AGE_BLOCK
                    || blck.block_type == HOP_COUNT_BLOCK
                    || blck.block_type == PREVIOUS_NODE_BLOCK)
            {
                errors.push(Error::BundleError(
                    "PreviousNode, BundleAge and HopCound blocks must not occure multiple times"
                        .to_string(),
                ));
            }
        }
        if self.primary.creation_timestamp.dtntime() == 0 && !b_types.contains(&BUNDLE_AGE_BLOCK) {
            errors.push(Error::BundleError(
                "Creation Timestamp is zero, but no Bundle Age block is present".to_string(),
            ));
        }
        if self.payload().is_none() {
            errors.push(Error::BundleError("Missing Payload Block".to_string()));
        } else if self.canonicals.last().unwrap().block_type != PAYLOAD_BLOCK {
            errors.push(Error::BundleError(
                "Last block must be a payload block".to_string(),
            ));
        }

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }
    /// Sort canonical blocks by block number
    pub fn sort_canonicals(&mut self) {
        self.canonicals
            .sort_by(|a, b| b.block_number.cmp(&a.block_number));
    }
    fn next_canonical_block_number(&self) -> u64 {
        let mut highest_block_number = 1;
        for c in self.canonicals.iter() {
            highest_block_number = cmp::max(highest_block_number, c.block_number);
        }
        highest_block_number + 1
    }

    /// Automatically assign a block number and add canonical block to bundle
    pub fn add_canonical_block(&mut self, mut cblock: CanonicalBlock) {
        // TODO: report errors
        if (cblock.block_type == PAYLOAD_BLOCK
            || cblock.block_type == HOP_COUNT_BLOCK
            || cblock.block_type == BUNDLE_AGE_BLOCK
            || cblock.block_type == PREVIOUS_NODE_BLOCK)
            && self.extension_block_by_type(cblock.block_type).is_some()
        {
            return;
        }
        let block_num = if cblock.block_type == PAYLOAD_BLOCK {
            crate::canonical::PAYLOAD_BLOCK_NUMBER
        } else {
            self.next_canonical_block_number()
        };
        cblock.block_number = block_num;
        self.canonicals.push(cblock);
        self.sort_canonicals();
    }
    /// Checks whether the bundle is an administrative record
    pub fn is_administrative_record(&self) -> bool {
        self.primary
            .bundle_control_flags
            .flags()
            .contains(BundleControlFlags::BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD)
    }
    /// Return payload of bundle if an payload block exists and carries data.
    pub fn payload(&self) -> Option<&ByteBuffer> {
        self.extension_block_by_type(crate::canonical::PAYLOAD_BLOCK)?
            .payload_data()
    }

    /// Sets or updates the payload block
    pub fn set_payload_block(&mut self, payload: CanonicalBlock) {
        self.canonicals
            .retain(|c| c.block_type != crate::canonical::PAYLOAD_BLOCK);
        self.add_canonical_block(payload);
    }

    /// Sets or updates the payload
    pub fn set_payload(&mut self, payload: ByteBuffer) {
        if let Some(pb) = self.extension_block_by_type_mut(crate::canonical::PAYLOAD_BLOCK) {
            pb.set_data(crate::canonical::CanonicalData::Data(payload));
        } else {
            let new_payload =
                crate::canonical::new_payload_block(BlockControlFlags::empty(), payload);
            self.set_payload_block(new_payload);
        }
    }
    /// Sets the given CRCType for each block. The crc value
    /// is calculated on-the-fly before serializing.
    pub fn set_crc(&mut self, crc_type: CrcRawType) {
        self.primary.set_crc_type(crc_type);
        for b in &mut self.canonicals {
            b.set_crc_type(crc_type);
        }
    }
    /// Check whether a bundle has only valid CRC checksums in all blocks.
    pub fn crc_valid(&mut self) -> bool {
        if !self.primary.check_crc() {
            return false;
        }
        for b in &mut self.canonicals {
            if !b.check_crc() {
                return false;
            }
        }
        true
    }
    /// Calculate crc for all blocks.
    pub fn calculate_crc(&mut self) {
        self.primary.update_crc();
        for b in &mut self.canonicals {
            b.update_crc();
        }
    }

    /// Get first extension block matching the block type
    pub fn extension_block_by_type(
        &self,
        block_type: CanonicalBlockType,
    ) -> Option<&CanonicalBlock> {
        self.canonicals
            .iter()
            .find(|&b| b.block_type == block_type && b.extension_validation().is_ok())
    }
    /// Get mutable reference for first extension block matching the block type
    pub fn extension_block_by_type_mut(
        &mut self,
        block_type: CanonicalBlockType,
    ) -> Option<&mut CanonicalBlock> {
        self.canonicals
            .iter_mut()
            .find(|b| b.block_type == block_type && b.extension_validation().is_ok())
    }

    /// Serialize bundle as CBOR encoded byte buffer.
    pub fn to_cbor(&mut self) -> ByteBuffer {
        self.calculate_crc();
        let mut bytebuf = serde_cbor::to_vec(&self).expect("Error serializing bundle as cbor.");
        bytebuf[0] = 0x9f; // TODO: fix hack, indefinite-length array encoding
        bytebuf.push(0xff); // break mark
        bytebuf
    }

    /// Serialize bundle as JSON encoded string.
    pub fn to_json(&mut self) -> String {
        self.calculate_crc();
        serde_json::to_string(&self).unwrap()
    }

    /// ID returns a kind of uniquene representation of this bundle, containing
    /// the souce node and creation timestamp. If this bundle is a fragment, the
    /// offset is also present.
    pub fn id(&self) -> String {
        let src = self.primary.source.to_string();
        let mut id = format!(
            "{}-{}-{}",
            // should IDs contain trailing '/' in the source?
            // src.strip_suffix('/').unwrap_or(&src),
            src,
            self.primary.creation_timestamp.dtntime(),
            self.primary.creation_timestamp.seqno(),
            //self.primary.destination
        );
        if self.primary.has_fragmentation() {
            id = format!("{}-{}", id, self.primary.fragmentation_offset);
        }
        id
    }

    /// Update extension blocks such as hop count, bundle age and previous node.
    /// Return true if all successful, omit missing blocks.
    /// Return false if hop count is exceeded, bundle age exceeds life time or bundle lifetime itself is exceeded
    pub fn update_extensions(&mut self, local_node: EndpointID, residence_time: u128) -> bool {
        if let Some(hcblock) = self.extension_block_by_type_mut(HOP_COUNT_BLOCK) {
            hcblock.hop_count_increase();
            if hcblock.hop_count_exceeded() {
                return false;
            }
        }
        if let Some(pnblock) = self.extension_block_by_type_mut(PREVIOUS_NODE_BLOCK) {
            pnblock.previous_node_update(local_node);
        }
        if let Some(bablock) = self.extension_block_by_type_mut(BUNDLE_AGE_BLOCK) {
            if let Some(ba_orig) = bablock.bundle_age_get() {
                bablock.bundle_age_update(ba_orig + residence_time);
                if ba_orig + residence_time > self.primary.lifetime.as_micros() {
                    // TODO: check lifetime exceeded calculations with rfc
                    return false;
                }
            }
        }
        !self.primary.is_lifetime_exceeded()
    }

    /// Return the previous node of a bundle should a Previous Node Block exist
    pub fn previous_node(&self) -> Option<&EndpointID> {
        let pnblock = self.extension_block_by_type(PREVIOUS_NODE_BLOCK)?;
        pnblock.previous_node_get()
    }
}

impl fmt::Display for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}_{}", self.id(), self.primary.destination)
    }
}

/// Deserialize from CBOR byte buffer.
impl TryFrom<ByteBuffer> for Bundle {
    type Error = Error;

    fn try_from(item: ByteBuffer) -> Result<Self, Self::Error> {
        match serde_cbor::from_slice(&item) {
            Ok(bndl) => Ok(bndl),
            Err(err) => Err(err.into()),
        }
    }
}

/// Deserialize from CBOR byte slice.
impl TryFrom<&[u8]> for Bundle {
    type Error = Error;

    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        match serde_cbor::from_slice(item) {
            Ok(bndl) => Ok(bndl),
            Err(err) => Err(err.into()),
        }
    }
}

/// Deserialize from JSON string.
impl TryFrom<String> for Bundle {
    type Error = Error;

    fn try_from(item: String) -> Result<Self, Self::Error> {
        match serde_json::from_str(&item) {
            Ok(bndl) => Ok(bndl),
            Err(err) => Err(err.into()),
        }
    }
}

/// Creates a new bundle with the given endpoints, a hop count block
///  and a payload block.
/// CRC is set to CrcNo by default and the lifetime is set to 60 * 60 seconds.
pub fn new_std_payload_bundle(src: EndpointID, dst: EndpointID, data: ByteBuffer) -> Bundle {
    let flags: BundleControlFlags = BundleControlFlags::BUNDLE_MUST_NOT_FRAGMENTED
        | BundleControlFlags::BUNDLE_STATUS_REQUEST_DELIVERY;
    let pblock = crate::primary::PrimaryBlockBuilder::default()
        .bundle_control_flags(flags.bits())
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(CreationTimestamp::now())
        .lifetime(core::time::Duration::from_secs(60 * 60))
        .build()
        .unwrap();
    let mut b = crate::bundle::Bundle::new(
        pblock,
        vec![
            new_payload_block(BlockControlFlags::empty(), data),
            new_hop_count_block(2, BlockControlFlags::empty(), 32),
        ],
    );
    b.set_crc(crate::crc::CRC_NO);
    b.sort_canonicals();
    b
}
