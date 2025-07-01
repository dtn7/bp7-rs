use crate::error::Error;
use crate::error::ErrorList;

use super::bundle::*;
use super::crc::{CrcBlock, CrcRawType, CrcValue, CRC_16, CRC_32, CRC_NO};
use super::eid::*;
use super::flags::*;
use core::convert::TryInto;
use core::fmt;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

/******************************
 *
 * Canonical Block
 *
 ******************************/

pub type CanonicalBlockType = u64;

pub(crate) const PAYLOAD_BLOCK_NUMBER: CanonicalBlockType = 1;

// PAYLOAD_BLOCK is a BlockType for a payload block as defined in 4.2.3.
pub const PAYLOAD_BLOCK: CanonicalBlockType = 1;
/*
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
*/
// PREVIOUS_NODE_BLOCK is a BlockType for a Previous Node block as defined
// in section 4.3.1.
pub const PREVIOUS_NODE_BLOCK: CanonicalBlockType = 6;

// BUNDLE_AGE_BLOCK is a BlockType for a Bundle Age block as defined in
// section 4.3.2.
pub const BUNDLE_AGE_BLOCK: CanonicalBlockType = 7;

// HOP_COUNT_BLOCK is a BlockType for a Hop Count block as defined in
// section 4.3.3.
pub const HOP_COUNT_BLOCK: CanonicalBlockType = 10;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CanonicalBlockBuilder {
    block_type: CanonicalBlockType,
    block_number: u64,
    block_control_flags: BlockControlFlagsType,
    crc: CrcValue,
    data: Option<CanonicalData>,
}

#[derive(Error, Debug)]
pub enum CanonicalBuilderError {
    #[error("Missing canoncial data")]
    MissingData,
}

impl CanonicalBlockBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn block_type(mut self, block_type: CanonicalBlockType) -> Self {
        self.block_type = block_type;
        self
    }
    pub fn block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number;
        self
    }
    pub fn block_control_flags(mut self, block_control_flags: BlockControlFlagsType) -> Self {
        self.block_control_flags = block_control_flags;
        self
    }
    pub fn crc(mut self, crc: CrcValue) -> Self {
        self.crc = crc;
        self
    }
    pub fn data(mut self, data: CanonicalData) -> Self {
        self.data = Some(data);
        self
    }
    pub fn build(self) -> Result<CanonicalBlock, CanonicalBuilderError> {
        if let Some(data) = self.data {
            Ok(CanonicalBlock {
                block_type: self.block_type,
                block_number: self.block_number,
                block_control_flags: self.block_control_flags,
                crc: self.crc,
                data,
            })
        } else {
            Err(CanonicalBuilderError::MissingData)
        }
    }
}

//#[derive(Debug, Serialize_tuple, Deserialize_tuple, Clone)]
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalBlock {
    pub block_type: CanonicalBlockType,
    pub block_number: u64,
    pub block_control_flags: BlockControlFlagsType,
    pub crc: CrcValue,
    data: CanonicalData,
}

impl Serialize for CanonicalBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let crc_code = self.crc.to_code();
        let num_elems = if crc_code == CRC_NO { 5 } else { 6 };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.block_type)?;
        seq.serialize_element(&self.block_number)?;
        seq.serialize_element(&self.block_control_flags)?;
        seq.serialize_element(&crc_code)?;
        //seq.serialize_element(&self.data)?;
        match self.data {
            CanonicalData::Data(ref payload) => {
                seq.serialize_element(&serde_bytes::Bytes::new(payload))?;
            }
            CanonicalData::Unknown(ref payload) => {
                seq.serialize_element(&serde_bytes::Bytes::new(payload))?;
            }
            _ => {
                seq.serialize_element(&serde_bytes::Bytes::new(
                    &serde_cbor::to_vec(&self.data).unwrap(),
                ))?;
            }
        };

        if self.crc.has_crc() {
            seq.serialize_element(&serde_bytes::Bytes::new(self.crc.bytes().unwrap()))?;
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
                formatter.write_str("CanonicalBlock")
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
                let block_control_flags: BlockControlFlagsType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let crc_type: CrcRawType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                // get payload as raw byte buffer
                let raw_payload = seq
                    .next_element::<serde_bytes::ByteBuf>()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?
                    .into_vec();

                // parse nested payload according to block_type
                let data = if block_type == PAYLOAD_BLOCK {
                    //dbg!(crate::helpers::hexify(&raw_payload));
                    CanonicalData::Data(raw_payload)
                } else if block_type == BUNDLE_AGE_BLOCK {
                    CanonicalData::BundleAge(serde_cbor::from_slice::<u64>(&raw_payload).map_err(
                        |err| {
                            de::Error::custom(format!("error decoding bundle age block: {}", err))
                        },
                    )?)
                } else if block_type == HOP_COUNT_BLOCK {
                    let hc: (u8, u8) = serde_cbor::from_slice(&raw_payload).map_err(|err| {
                        de::Error::custom(format!("error decoding hop count block: {}", err))
                    })?;
                    CanonicalData::HopCount(hc.0, hc.1)
                } else if block_type == PREVIOUS_NODE_BLOCK {
                    CanonicalData::PreviousNode(serde_cbor::from_slice(&raw_payload).map_err(
                        |err| {
                            de::Error::custom(format!(
                                "error decoding previous node block: {}",
                                err
                            ))
                        },
                    )?)
                } else {
                    CanonicalData::Unknown(raw_payload)
                };
                let crc = if crc_type == CRC_NO {
                    CrcValue::CrcNo
                } else if crc_type == CRC_16 {
                    let crcbuf: ByteBuffer = seq
                        .next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(5, &self))?
                        .into_vec();
                    let mut outbuf: [u8; 2] = [0; 2];
                    if crcbuf.len() != outbuf.len() {
                        return Err(de::Error::invalid_length(5, &self));
                    }
                    outbuf.copy_from_slice(&crcbuf);
                    CrcValue::Crc16(outbuf)
                } else if crc_type == CRC_32 {
                    let crcbuf: ByteBuffer = seq
                        .next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(5, &self))?
                        .into_vec();
                    let mut outbuf: [u8; 4] = [0; 4];
                    if crcbuf.len() != outbuf.len() {
                        return Err(de::Error::invalid_length(5, &self));
                    }
                    outbuf.copy_from_slice(&crcbuf);
                    CrcValue::Crc32(outbuf)
                } else {
                    CrcValue::Unknown(crc_type)
                };

                Ok(CanonicalBlock {
                    block_type,
                    block_number,
                    block_control_flags,
                    crc,
                    data,
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

impl CrcBlock for CanonicalBlock {
    fn crc_value(&self) -> &CrcValue {
        &self.crc
    }
    fn set_crc(&mut self, crc: CrcValue) {
        self.crc = crc;
    }
}
impl Block for CanonicalBlock {
    fn to_cbor(&self) -> ByteBuffer {
        serde_cbor::to_vec(&self).unwrap()
    }
}

pub fn new_canonical_block(
    block_type: CanonicalBlockType,
    block_number: u64,
    block_control_flags: BlockControlFlagsType,
    data: CanonicalData,
) -> CanonicalBlock {
    CanonicalBlock {
        block_type,
        block_number,
        block_control_flags,
        crc: CrcValue::CrcNo,
        data,
    }
}

impl CanonicalBlock {
    pub fn new() -> CanonicalBlock {
        CanonicalBlock {
            block_type: PAYLOAD_BLOCK,
            block_number: 0,
            block_control_flags: 0,
            crc: CrcValue::CrcNo,
            data: CanonicalData::Data(Vec::new()),
        }
    }

    pub fn validate(&self) -> Result<(), ErrorList> {
        let mut errors: ErrorList = Vec::new();

        if let Err(err) = self.block_control_flags.validate() {
            errors.push(err);
        }

        if let Err(err) = self.extension_validation() {
            errors.push(err);
        }
        if self.has_crc() && !self.clone().check_crc() {
            errors.push(Error::CanonicalBlockError("CRC check failed".to_string()));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    pub fn extension_validation(&self) -> Result<(), Error> {
        // TODO: reimpl checks
        match &self.data {
            CanonicalData::Data(_) => {
                if self.block_type != PAYLOAD_BLOCK {
                    return Err(Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
                if self.block_number != 1 {
                    return Err(Error::CanonicalBlockError(
                        "Payload Block's block number is not one".to_string(),
                    ));
                }
            }
            CanonicalData::BundleAge(_) => {
                if self.block_type != BUNDLE_AGE_BLOCK {
                    return Err(Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
            }
            CanonicalData::HopCount(_, _) => {
                if self.block_type != HOP_COUNT_BLOCK {
                    return Err(Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
            }
            CanonicalData::PreviousNode(prev_eid) => {
                if self.block_type != PREVIOUS_NODE_BLOCK {
                    return Err(Error::CanonicalBlockError(
                        "Payload data not matching payload type".to_string(),
                    ));
                }
                if let Err(err) = prev_eid.validate() {
                    return Err(err.into());
                }
            }
            CanonicalData::Unknown(_) => {
                // Nothing to check as content is unknown
            }
            CanonicalData::DecodingError => {
                return Err(Error::CanonicalBlockError("Unknown data".to_string()));
            }
        }
        /*if (self.block_type > 9 && self.block_type < 192) || (self.block_type > 255) {
            return Some(Bp7Error::CanonicalBlockError(
                "Unknown block type".to_string(),
            ));
        }*/

        Ok(())
    }
    pub fn data(&self) -> &CanonicalData {
        &self.data
    }
    pub fn set_data(&mut self, data: CanonicalData) {
        self.data = data;
    }
    pub fn payload_data(&self) -> Option<&ByteBuffer> {
        match &self.data {
            CanonicalData::Data(data) => Some(data),
            _ => None,
        }
    }
    pub fn hop_count_get(&self) -> Option<(u8, u8)> {
        if self.block_type == HOP_COUNT_BLOCK {
            if let CanonicalData::HopCount(hc_limit, hc_count) = self.data() {
                return Some((*hc_limit, *hc_count));
            }
        }
        None
    }
    pub fn hop_count_increase(&mut self) -> bool {
        if let Some((hc_limit, mut hc_count)) = self.hop_count_get() {
            hc_count += 1;
            self.set_data(CanonicalData::HopCount(hc_limit, hc_count));
            return true;
        }
        false
    }
    pub fn hop_count_exceeded(&self) -> bool {
        if self.block_type == HOP_COUNT_BLOCK {
            if let CanonicalData::HopCount(hc_limit, hc_count) = self.data() {
                if *hc_count > *hc_limit {
                    return true;
                }
            }
        }
        false
    }
    pub fn bundle_age_update(&mut self, age: u128) -> bool {
        if self.bundle_age_get().is_some() {
            self.set_data(CanonicalData::BundleAge(age.try_into().unwrap()));
            return true;
        }
        false
    }
    pub fn bundle_age_get(&self) -> Option<u128> {
        if self.block_type == BUNDLE_AGE_BLOCK {
            if let CanonicalData::BundleAge(age) = self.data() {
                return Some((*age).into());
            }
        }
        None
    }
    pub fn previous_node_update(&mut self, nodeid: EndpointID) -> bool {
        if self.previous_node_get().is_some() {
            self.set_data(CanonicalData::PreviousNode(nodeid));
            return true;
        }
        false
    }
    pub fn previous_node_get(&self) -> Option<&EndpointID> {
        if self.block_type == PREVIOUS_NODE_BLOCK {
            if let CanonicalData::PreviousNode(eid) = self.data() {
                return Some(eid);
            }
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)] // Order of probable occurence, serde tries decoding in untagged enums in this order, circumvented by intelligent canonical deserializer
pub enum CanonicalData {
    HopCount(u8, u8),
    Data(#[serde(with = "serde_bytes")] ByteBuffer),
    BundleAge(u64),
    PreviousNode(EndpointID),
    Unknown(#[serde(with = "serde_bytes")] ByteBuffer),
    DecodingError,
}
impl CanonicalData {
    pub fn to_cbor(&self) -> ByteBuffer {
        serde_cbor::to_vec(&self).expect("CanonicalData encoding error")
    }
}

/// the hop count limit must be between 1 and 255 (RFC 9171: Sec. 4.4.3)
pub fn new_hop_count_block(block_number: u64, bcf: BlockControlFlags, limit: u8) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(HOP_COUNT_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf.bits())
        .data(CanonicalData::HopCount(limit, 0))
        .build()
        .unwrap()
}

pub fn new_payload_block(bcf: BlockControlFlags, data: ByteBuffer) -> CanonicalBlock {
    CanonicalBlockBuilder::default()
        .block_type(PAYLOAD_BLOCK)
        .block_number(PAYLOAD_BLOCK_NUMBER)
        .block_control_flags(bcf.bits())
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
        .block_control_flags(bcf.bits())
        .data(CanonicalData::PreviousNode(prev))
        .build()
        .unwrap()
}

pub fn new_bundle_age_block(
    block_number: u64,
    bcf: BlockControlFlags,
    time_in_millis: u64,
) -> CanonicalBlock {
    /*CanonicalBlock {
        block_type: BUNDLE_AGE_BLOCK,
        crc_type: crate::crc::CRC_NO,
        block_number,
        block_control_flags: bcf,
        data: CanonicalData::BundleAge(time),
        crc: Vec::new(),
    }*/
    CanonicalBlockBuilder::default()
        .block_type(BUNDLE_AGE_BLOCK)
        .block_number(block_number)
        .block_control_flags(bcf.bits())
        .data(CanonicalData::BundleAge(time_in_millis))
        .build()
        .unwrap()
}
