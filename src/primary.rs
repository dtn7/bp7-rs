use crate::error::Error;
use crate::error::ErrorList;

use super::bundle::*;
use super::crc::*;
use super::dtntime::*;
use super::eid::*;
use super::flags::*;
use core::fmt;
use core::{convert::TryFrom, time::Duration};
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

/******************************
 *
 * Primary Block
 *
 ******************************/

#[derive(Error, Debug)]
pub enum PrimaryBuilderError {
    #[error("no destination endpoint was provided")]
    NoDestination,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PrimaryBlockBuilder {
    bundle_control_flags: BundleControlFlagsType,
    crc: CrcValue,
    destination: EndpointID,
    source: EndpointID,
    report_to: EndpointID,
    creation_timestamp: CreationTimestamp,
    lifetime: Duration,
    fragmentation_offset: FragOffsetType,
    total_data_length: TotalDataLengthType,
}
impl PrimaryBlockBuilder {
    pub fn new() -> Self {
        // let mut builder = PrimaryBlockBuilder::default();
        // should this be set by default?
        // builder.creation_timestamp = CreationTimestamp::now();
        PrimaryBlockBuilder::default()
    }
    pub fn bundle_control_flags(mut self, flags: BundleControlFlagsType) -> Self {
        self.bundle_control_flags = flags;
        self
    }
    pub fn crc(mut self, crc: CrcValue) -> Self {
        self.crc = crc;
        self
    }
    pub fn destination(mut self, dest: EndpointID) -> Self {
        self.destination = dest;
        self
    }
    pub fn source(mut self, source: EndpointID) -> Self {
        self.source = source;
        self
    }
    pub fn report_to(mut self, report_to: EndpointID) -> Self {
        self.report_to = report_to;
        self
    }
    pub fn creation_timestamp(mut self, creation_timestamp: CreationTimestamp) -> Self {
        self.creation_timestamp = creation_timestamp;
        self
    }
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }
    pub fn fragmentation_offset(mut self, offset: FragOffsetType) -> Self {
        self.fragmentation_offset = offset;
        self
    }
    pub fn total_data_length(mut self, length: TotalDataLengthType) -> Self {
        self.total_data_length = length;
        self
    }
    pub fn build(self) -> Result<PrimaryBlock, PrimaryBuilderError> {
        if self.destination == EndpointID::none() {
            Err(PrimaryBuilderError::NoDestination)
        } else {
            Ok(PrimaryBlock {
                version: DTN_VERSION,
                bundle_control_flags: self.bundle_control_flags,
                crc: self.crc,
                destination: self.destination,
                source: self.source,
                report_to: self.report_to,
                creation_timestamp: self.creation_timestamp,
                lifetime: self.lifetime,
                fragmentation_offset: self.fragmentation_offset,
                total_data_length: self.total_data_length,
            })
        }
    }
}

//#[derive(Debug, Serialize_tuple, Deserialize_tuple, Clone)]
#[derive(Debug, Clone, PartialEq)]
pub struct PrimaryBlock {
    version: DtnVersionType,
    pub bundle_control_flags: BundleControlFlagsType,
    pub crc: CrcValue,
    pub destination: EndpointID,
    pub source: EndpointID,
    pub report_to: EndpointID,
    pub creation_timestamp: CreationTimestamp,
    /// in milliseconds
    pub lifetime: Duration,
    pub fragmentation_offset: FragOffsetType,
    pub total_data_length: TotalDataLengthType,
}

impl Serialize for PrimaryBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = if !self.crc.has_crc() && !self.has_fragmentation() {
            8
        } else if self.crc.has_crc() && !self.has_fragmentation() {
            9
        } else if !self.crc.has_crc() && self.has_fragmentation() {
            10
        } else {
            11
        };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.version)?;
        seq.serialize_element(&self.bundle_control_flags)?;
        seq.serialize_element(&self.crc.to_code())?;
        seq.serialize_element(&self.destination)?;
        seq.serialize_element(&self.source)?;
        seq.serialize_element(&self.report_to)?;
        seq.serialize_element(&self.creation_timestamp)?;
        seq.serialize_element(&(self.lifetime.as_millis() as u64))?;
        if self.has_fragmentation() {
            seq.serialize_element(&self.fragmentation_offset)?;
            seq.serialize_element(&self.total_data_length)?;
        }

        if self.crc.has_crc() {
            seq.serialize_element(&serde_bytes::Bytes::new(self.crc.bytes().unwrap()))?;
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for PrimaryBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrimaryBlockVisitor;

        impl<'de> Visitor<'de> for PrimaryBlockVisitor {
            type Value = PrimaryBlock;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("PrimaryBlock")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let version: DtnVersionType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let bundle_control_flags: BundleControlFlagsType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let crc_type: CrcRawType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let destination: EndpointID = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let source: EndpointID = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let report_to: EndpointID = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;
                let creation_timestamp: CreationTimestamp = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(6, &self))?;
                let lifetime_u64: u64 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(7, &self))?;
                let lifetime = Duration::from_millis(lifetime_u64);

                let rest = seq.size_hint().unwrap_or(0);
                let mut fragmentation_offset: FragOffsetType = 0;
                let mut total_data_length: TotalDataLengthType = 0;

                if rest > 1 {
                    fragmentation_offset = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(8, &self))?;
                    total_data_length = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(9, &self))?;
                }
                let crc = if crc_type == CRC_NO {
                    CrcValue::CrcNo
                } else if crc_type == CRC_16 {
                    let crcbuf: ByteBuffer = seq
                        .next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(7 + rest, &self))?
                        .into_vec();
                    let mut outbuf: [u8; 2] = [0; 2];
                    if crcbuf.len() != outbuf.len() {
                        return Err(de::Error::invalid_length(7 + rest, &self));
                    }
                    outbuf.copy_from_slice(&crcbuf);
                    CrcValue::Crc16(outbuf)
                } else if crc_type == CRC_32 {
                    let crcbuf: ByteBuffer = seq
                        .next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(7 + rest, &self))?
                        .into_vec();
                    let mut outbuf: [u8; 4] = [0; 4];
                    if crcbuf.len() != outbuf.len() {
                        return Err(de::Error::invalid_length(7 + rest, &self));
                    }
                    outbuf.copy_from_slice(&crcbuf);
                    CrcValue::Crc32(outbuf)
                } else {
                    CrcValue::Unknown(crc_type)
                };
                Ok(PrimaryBlock {
                    version,
                    bundle_control_flags,
                    crc,
                    destination,
                    source,
                    report_to,
                    creation_timestamp,
                    lifetime,
                    fragmentation_offset,
                    total_data_length,
                })
            }
        }

        deserializer.deserialize_any(PrimaryBlockVisitor)
    }
}
impl Default for PrimaryBlock {
    fn default() -> Self {
        PrimaryBlock::new()
    }
}

impl PrimaryBlock {
    pub fn new() -> PrimaryBlock {
        PrimaryBlock {
            version: DTN_VERSION,
            bundle_control_flags: 0,
            crc: CrcValue::CrcNo,
            destination: EndpointID::new(),
            source: EndpointID::new(),
            report_to: EndpointID::new(),
            creation_timestamp: CreationTimestamp::new(),
            lifetime: Duration::new(0, 0),
            fragmentation_offset: 0,
            total_data_length: 0,
        }
    }

    pub fn has_fragmentation(&self) -> bool {
        self.bundle_control_flags
            .contains(BundleControlFlags::BUNDLE_IS_FRAGMENT)
    }
    pub fn is_lifetime_exceeded(&self) -> bool {
        if self.creation_timestamp.dtntime() == 0 {
            return false;
        }

        let now = crate::dtn_time_now();
        self.creation_timestamp.dtntime() + (self.lifetime.as_millis() as u64) <= now
    }
    pub fn validate(&self) -> Result<(), ErrorList> {
        let mut errors: ErrorList = Vec::new();

        if self.version != DTN_VERSION {
            errors.push(Error::PrimaryBlockError(format!(
                "Wrong version, {} instead of {}",
                self.version, DTN_VERSION
            )));
        }

        // bundle control flags
        if let Err(mut err) = self.bundle_control_flags.validate() {
            errors.append(&mut err);
        }

        if let Err(chk_err) = self.destination.validate() {
            errors.push(chk_err.into());
        }

        if let Err(chk_err) = self.source.validate() {
            errors.push(chk_err.into());
        }
        if let Err(chk_err) = self.report_to.validate() {
            errors.push(chk_err.into());
        }

        if self.has_crc() && !self.clone().check_crc() {
            errors.push(Error::PrimaryBlockError("CRC check failed".to_string()));
        }

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }
}

impl CrcBlock for PrimaryBlock {
    fn crc_value(&self) -> &CrcValue {
        &self.crc
    }
    fn set_crc(&mut self, crc: CrcValue) {
        self.crc = crc;
    }
}
impl Block for PrimaryBlock {
    fn to_cbor(&self) -> ByteBuffer {
        serde_cbor::to_vec(&self).expect("Error exporting primary block to cbor")
    }
}
pub fn new_primary_block(
    dst: &str,
    src: &str,
    creation_timestamp: CreationTimestamp,
    lifetime: Duration,
) -> PrimaryBlock {
    let dst_eid = EndpointID::try_from(dst).unwrap();
    let src_eid = EndpointID::try_from(src).unwrap();

    PrimaryBlock {
        version: DTN_VERSION,
        bundle_control_flags: 0,
        crc: CrcValue::CrcNo,
        destination: dst_eid,
        source: src_eid.clone(),
        report_to: src_eid,
        creation_timestamp,
        lifetime,
        fragmentation_offset: 0,
        total_data_length: 0,
    }
}
