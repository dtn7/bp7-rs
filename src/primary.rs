use super::bundle::*;
use super::crc::*;
use super::dtntime::*;
use super::eid::*;
use derive_builder::Builder;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

/******************************
 *
 * Primary Block
 *
 ******************************/

//#[derive(Debug, Serialize_tuple, Deserialize_tuple, Clone)]
#[derive(Debug, Clone, PartialEq, Builder)]
#[builder(default)]
pub struct PrimaryBlock {
    version: DtnVersionType,
    pub bundle_control_flags: BundleControlFlags,
    pub crc_type: CRCType,
    pub destination: EndpointID,
    pub source: EndpointID,
    pub report_to: EndpointID,
    pub creation_timestamp: CreationTimestamp,
    pub lifetime: LifetimeType,
    pub fragmentation_offset: FragOffsetType,
    pub total_data_length: TotalDataLengthType,
    crc: ByteBuffer,
}

impl Serialize for PrimaryBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = if self.crc_type == CRC_NO && !self.has_fragmentation() {
            8
        } else if self.crc_type != CRC_NO && !self.has_fragmentation() {
            9
        } else if self.crc_type == CRC_NO && self.has_fragmentation() {
            10
        } else {
            11
        };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.version)?;
        seq.serialize_element(&self.bundle_control_flags)?;
        seq.serialize_element(&self.crc_type)?;
        seq.serialize_element(&self.destination)?;
        seq.serialize_element(&self.source)?;
        seq.serialize_element(&self.report_to)?;
        seq.serialize_element(&self.creation_timestamp)?;
        seq.serialize_element(&self.lifetime)?;
        if self.has_fragmentation() {
            seq.serialize_element(&self.fragmentation_offset)?;
            seq.serialize_element(&self.total_data_length)?;
        }

        if self.crc_type != CRC_NO {
            seq.serialize_element(&serde_bytes::Bytes::new(&self.crc))?;
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
                formatter.write_str("packet")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let version: DtnVersionType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let bundle_control_flags: BundleControlFlags = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let crc_type: CRCType = seq
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
                let lifetime: LifetimeType = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(7, &self))?;

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

                let crc: ByteBuffer = if crc_type == CRC_NO {
                    Vec::new()
                } else {
                    seq.next_element::<serde_bytes::Bytes>()?
                        .ok_or_else(|| de::Error::invalid_length(7 + rest, &self))?
                        .to_owned()
                        .to_vec()
                };
                Ok(PrimaryBlock {
                    version,
                    bundle_control_flags,
                    crc_type,
                    destination,
                    source,
                    report_to,
                    creation_timestamp,
                    lifetime,
                    fragmentation_offset,
                    total_data_length,
                    crc,
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
            crc_type: CRC_NO,
            destination: EndpointID::new(),
            source: EndpointID::new(),
            report_to: EndpointID::new(),
            creation_timestamp: CreationTimestamp::new(),
            lifetime: 0,
            fragmentation_offset: 0,
            total_data_length: 0,
            crc: Vec::new(),
        }
    }

    pub fn has_fragmentation(&self) -> bool {
        self.bundle_control_flags.has(BUNDLE_IS_FRAGMENT)
    }
    pub fn validation_errors(&self) -> Option<Bp7ErrorList> {
        let mut errors: Bp7ErrorList = Vec::new();

        if self.version != DTN_VERSION {
            errors.push(Bp7Error::PrimaryBlockError(format!(
                "Wrong version, {} instead of {}",
                self.version, DTN_VERSION
            )));
        }

        // bundle control flags
        if let Some(mut err) = self.bundle_control_flags.validation_errors() {
            errors.append(&mut err);
        }

        if let Some(chk_err) = self.destination.validation_error() {
            errors.push(chk_err);
        }

        if let Some(chk_err) = self.source.validation_error() {
            errors.push(chk_err);
        }
        if let Some(chk_err) = self.report_to.validation_error() {
            errors.push(chk_err);
        }

        if !errors.is_empty() {
            return Some(errors);
        }
        None
    }
}

impl Block for PrimaryBlock {
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
        //serde_cbor::to_vec(&self.to_pvariant()).unwrap()
        serde_cbor::to_vec(&self).unwrap()
    }
}
pub fn new_primary_block(
    dst: String,
    src: String,
    creation_timestamp: CreationTimestamp,
    lifetime: u64,
) -> PrimaryBlock {
    let dst_eid = EndpointID::from(dst);
    let src_eid = EndpointID::from(src);

    PrimaryBlock {
        version: DTN_VERSION,
        bundle_control_flags: 0,
        crc_type: CRC_NO,
        destination: dst_eid,
        source: src_eid.clone(),
        report_to: src_eid,
        creation_timestamp,
        lifetime,
        fragmentation_offset: 0,
        total_data_length: 0,
        crc: Vec::new(),
    }
}
