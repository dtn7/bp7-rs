use super::bundle::*;
use super::crc::*;
use super::eid::*;
use derive_builder::Builder;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

/******************************
 *
 * Canonical Block
 *
 ******************************/

pub type CanonicalBlockType = u64;

// PAYLOAD_BLOCK is a BlockType for a payload block as defined in 4.2.3.
pub const PAYLOAD_BLOCK: CanonicalBlockType = 1;

// INTEGRITY_BLOCK is a BlockType defined in the Bundle Security Protocol
// specifiation.
pub const INTEGRITY_BLOCK: CanonicalBlockType = 2;

// CONFIDENTIALITY_BLOCK is a BlockType defined in the Bundle Security
// Protocol specifiation.
pub const CONFIDENTIALITY_BLOCK: CanonicalBlockType = 3;

// MANIFEST_BLOCK is a BlockType defined in the Manifest Extension Block
// specifiation.
pub const MANIFEST_BLOCK: CanonicalBlockType = 4;

// FLOW_LABEL_BLOCK is a BlockType defined in the Flow Label Extension Block
// specification.
pub const FLOW_LABEL_BLOCK: CanonicalBlockType = 6;

// PREVIOUS_NODE_BLOCK is a BlockType for a Previous Node block as defined
// in section 4.3.1.
pub const PREVIOUS_NODE_BLOCK: CanonicalBlockType = 7;

// BUNDLE_AGE_BLOCK is a BlockType for a Bundle Age block as defined in
// section 4.3.2.
pub const BUNDLE_AGE_BLOCK: CanonicalBlockType = 8;

// HOP_COUNT_BLOCK is a BlockType for a Hop Count block as defined in
// section 4.3.3.
pub const HOP_COUNT_BLOCK: CanonicalBlockType = 9;

//#[derive(Debug, Serialize_tuple, Deserialize_tuple, Clone)]
#[derive(Debug, Clone, PartialEq, Builder)]
#[builder(default)]
pub struct CanonicalBlock {
    pub block_type: CanonicalBlockType,
    pub block_number: u64,
    pub block_control_flags: BlockControlFlags,
    pub crc_type: CRCType,
    data: CanonicalData,
    crc: ByteBuffer,
}

impl Serialize for CanonicalBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = if self.crc_type == CRC_NO { 5 } else { 6 };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.block_type)?;
        seq.serialize_element(&self.block_number)?;
        seq.serialize_element(&self.block_control_flags)?;
        seq.serialize_element(&self.crc_type)?;
        seq.serialize_element(&self.data.clone())?;

        if self.crc_type != CRC_NO {
            seq.serialize_element(&serde_bytes::Bytes::new(&self.crc))?;
        }

        seq.end()
    }
}
impl<'de> Deserialize<'de> for CanonicalBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CanonicalBlockVisitor;

        impl<'de> Visitor<'de> for CanonicalBlockVisitor {
            type Value = CanonicalBlock;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("packet")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let block_type: CanonicalBlockType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let block_number: u64 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let block_control_flags: BlockControlFlags = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let crc_type: CRCType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let data: CanonicalData = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let crc: ByteBuffer = if crc_type == CRC_NO {
                    Vec::new()
                } else {
                    seq.next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(5, &self))?
                        .into_vec()
                };
                Ok(CanonicalBlock {
                    block_type,
                    block_number,
                    block_control_flags,
                    crc_type,
                    data,
                    crc,
                })
            }
        }

        deserializer.deserialize_any(CanonicalBlockVisitor)
    }
}
impl Default for CanonicalBlock {
    fn default() -> Self {
        CanonicalBlock::new()
    }
}
impl Block for CanonicalBlock {
    fn has_crc(&self) -> bool {
        self.crc_type != CRC_NO
    }
    fn crc(&self) -> ByteBuffer {
        self.crc.clone()
    }
    fn set_crc_type(&mut self, crc_type: CRCType) {
        self.crc_type = crc_type;
    }
    fn crc_type(&self) -> CRCType {
        self.crc_type
    }
    fn set_crc(&mut self, crc: ByteBuffer) {
        self.crc = crc;
    }
    fn to_cbor(&self) -> ByteBuffer {
        serde_cbor::to_vec(&self).unwrap()
    }
}

pub fn new_canonical_block(
    block_type: CanonicalBlockType,
    block_number: u64,
    block_control_flags: BlockControlFlags,
    data: CanonicalData,
) -> CanonicalBlock {
    CanonicalBlock {
        block_type,
        block_number,
        block_control_flags,
        crc_type: CRC_NO,
        data,
        crc: Vec::new(),
    }
}

impl CanonicalBlock {
    pub fn new() -> CanonicalBlock {
        CanonicalBlock {
            block_type: PAYLOAD_BLOCK,
            block_number: 0,
            block_control_flags: 0,
            crc_type: CRC_NO,
            data: CanonicalData::Data(Vec::new()),
            crc: Vec::new(),
        }
    }

    pub fn validation_errors(&self) -> Option<Bp7ErrorList> {
        let mut errors: Bp7ErrorList = Vec::new();

        if let Some(err) = self.block_control_flags.validation_error() {
            errors.push(err);
        }

        if let Some(err) = self.extension_validation_error() {
            errors.push(err);
        }

        if !errors.is_empty() {
            return Some(errors);
        }
        None
    }
    pub fn extension_validation_error(&self) -> Option<Bp7Error> {
        match &self.data {
            CanonicalData::Data(_) => {
                if self.block_type != PAYLOAD_BLOCK {
                    return Some(Bp7Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
                if self.block_number != 0 {
                    return Some(Bp7Error::CanonicalBlockError(
                        "Payload Block's block number is not zero".to_string(),
                    ));
                }
            }
            CanonicalData::BundleAge(_) => {
                if self.block_type != BUNDLE_AGE_BLOCK {
                    return Some(Bp7Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
            }
            CanonicalData::HopCount(_, _) => {
                if self.block_type != HOP_COUNT_BLOCK {
                    return Some(Bp7Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
            }
            CanonicalData::PreviousNode(prev_eid) => {
                if self.block_type != PREVIOUS_NODE_BLOCK {
                    return Some(Bp7Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
                if let Some(err) = prev_eid.validation_error() {
                    return Some(err);
                }
            }
        }
        if (self.block_type > 9 && self.block_type < 192) || (self.block_type > 255) {
            return Some(Bp7Error::CanonicalBlockError(
                "Unknown block type".to_string(),
            ));
        }

        None
    }
    pub fn get_data(&mut self) -> &CanonicalData {
        &self.data
    }
    pub fn set_data(&mut self, data: CanonicalData) {
        self.data = data;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)] // Order of probable occurence, serde tries decoding in untagged enums in this order
pub enum CanonicalData {
    Data(#[serde(with = "serde_bytes")] ByteBuffer),
    BundleAge(u64),
    HopCount(u32, u32),
    PreviousNode(EndpointID),
}

pub fn new_hop_count_block(
    block_number: u64,
    bcf: BlockControlFlags,
    limit: u32,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(HOP_COUNT_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf)
        .data(CanonicalData::HopCount(0, limit))
        .build()
        .unwrap()
}

pub fn new_payload_block(bcf: BlockControlFlags, data: ByteBuffer) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(PAYLOAD_BLOCK)
        .block_number(0)
        .block_control_flags(bcf)
        .data(CanonicalData::Data(data))
        .build()
        .unwrap()
}

pub fn new_previous_node_block(
    block_number: u64,
    bcf: BlockControlFlags,
    prev: EndpointID,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(PREVIOUS_NODE_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf)
        .data(CanonicalData::PreviousNode(prev))
        .build()
        .unwrap()
}

pub fn new_bundle_age_block(
    block_number: u64,
    bcf: BlockControlFlags,
    time: u64,
) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(BUNDLE_AGE_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf)
        .data(CanonicalData::BundleAge(time))
        .build()
        .unwrap()
}
