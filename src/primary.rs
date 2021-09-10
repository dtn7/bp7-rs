use super::bundle::*;
use super::crc::*;
use super::dtntime::*;
use super::eid::*;
use core::fmt;
use core::{convert::TryFrom, time::Duration};
use derive_builder::Builder;
#[cfg(feature = "mini")]
use minicbor::{decode, encode, Decode, Decoder, Encode, Encoder};
#[cfg(feature = "cbor_serde")]
use serde::de::{SeqAccess, Visitor};
#[cfg(feature = "cbor_serde")]
use serde::ser::{SerializeSeq, Serializer};
#[cfg(feature = "cbor_serde")]
use serde::{de, Deserialize, Deserializer, Serialize};

/******************************
 *
 * Primary Block
 *
 ******************************/

//#[derive(Debug, Serialize_tuple, Deserialize_tuple, Clone)]
#[derive(Debug, Clone, PartialEq, Builder)]
#[builder(default)]
#[builder(pattern = "owned")]
pub struct PrimaryBlock {
    version: DtnVersionType,
    pub bundle_control_flags: BundleControlFlags,
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

impl encode::Encode for PrimaryBlock {
    fn encode<W: encode::Write>(&self, e: &mut Encoder<W>) -> Result<(), encode::Error<W::Error>> {
        let num_elems = if !self.crc.has_crc() && !self.has_fragmentation() {
            8
        } else if self.crc.has_crc() && !self.has_fragmentation() {
            9
        } else if !self.crc.has_crc() && self.has_fragmentation() {
            10
        } else {
            11
        };

        e.array(num_elems)?
            .u32(self.version)?
            .u64(self.bundle_control_flags)?
            .u8(self.crc.to_code())?
            .encode(&self.destination)?
            .encode(&self.source)?
            .encode(&self.report_to)?
            .encode(&self.creation_timestamp)?
            .u64(self.lifetime.as_millis() as u64)?;
        if self.has_fragmentation() {
            e.u64(self.fragmentation_offset)?
                .u64(self.total_data_length)?;
        }
        if self.crc.has_crc() {
            e.bytes(self.crc.bytes().unwrap())?;
        }
        e.ok()
    }
}
#[cfg(feature = "mini")]
impl<'b> Decode<'b> for PrimaryBlock {
    fn decode(d: &mut Decoder<'b>) -> Result<Self, decode::Error> {
        if let Some(num_elems) = d.array()? {
            if num_elems < 8 || num_elems > 11 {
                return Err(minicbor::decode::Error::Message(
                    "invalid primary block length",
                ));
            }
            let version = d.u32()?;
            let bundle_control_flags = d.u64()?;
            let crc_code = d.u8()?;
            let destination: EndpointID = d.decode()?;
            let source: EndpointID = d.decode()?;
            let report_to: EndpointID = d.decode()?;
            let creation_timestamp: CreationTimestamp = d.decode()?;
            let lifetime = Duration::from_millis(d.u64()?);
            let fragmentation_offset = if num_elems >= 10 { d.u64()? } else { 0 };
            let total_data_length = if num_elems >= 10 { d.u64()? } else { 0 };

            let crc = if crc_code == CRC_NO {
                CrcValue::CrcNo
            } else if crc_code == CRC_16 {
                let crcbuf = d.bytes()?;
                let mut outbuf: [u8; 2] = [0; 2];
                if crcbuf.len() != outbuf.len() {
                    return Err(minicbor::decode::Error::Message("crc error"));
                }
                outbuf.copy_from_slice(&crcbuf);
                CrcValue::Crc16(outbuf)
            } else if crc_code == CRC_32 {
                let crcbuf = d.bytes()?;

                let mut outbuf: [u8; 4] = [0; 4];
                if crcbuf.len() != outbuf.len() {
                    return Err(minicbor::decode::Error::Message("crc error"));
                }
                outbuf.copy_from_slice(&crcbuf);
                CrcValue::Crc32(outbuf)
            } else {
                CrcValue::Unknown(crc_code)
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
        } else {
            Err(minicbor::decode::Error::Message("canonical block"))
        }
    }
}
#[cfg(feature = "cbor_serde")]
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
#[cfg(feature = "cbor_serde")]
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
                let bundle_control_flags: BundleControlFlags = seq
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
        self.bundle_control_flags.has(BUNDLE_IS_FRAGMENT)
    }
    pub fn is_lifetime_exceeded(&self) -> bool {
        if self.creation_timestamp.dtntime() == 0 {
            return false;
        }

        let now = crate::dtn_time_now();
        self.creation_timestamp.dtntime() + (self.lifetime.as_millis() as u64) <= now
    }
    pub fn validate(&self) -> Result<(), Bp7ErrorList> {
        let mut errors: Bp7ErrorList = Vec::new();

        if self.version != DTN_VERSION {
            errors.push(Bp7Error::PrimaryBlockError(format!(
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
        if cfg!(feature = "cbor_serde") {
            serde_cbor::to_vec(&self).expect("Error exporting primary block to cbor")
        } else if cfg!(feature = "mini") {
            minicbor::to_vec(&self).unwrap()
        } else {
            unimplemented!()
        }
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
