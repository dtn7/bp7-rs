
use crate::bundle::ByteBuffer;
use crate::*;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

use crate::bundle::BUNDLE_REQUEST_STATUS_TIME;
use crate::bundle::{Bundle, BundleValidation};

use crate::dtntime::CreationTimestamp;
use crate::dtntime::DtnTime;
use crate::eid::EndpointID;
pub type AdministrativeRecordTypeCode = u32;

pub const BUNDLE_STATUS_REPORT_TYPE_CODE: AdministrativeRecordTypeCode = 1;

#[derive(Debug, Clone, PartialEq)]
pub enum AdministrativeRecord {
    BundleStatusReport(StatusReport),
    Unknown(AdministrativeRecordTypeCode, ByteBuffer),
    Mismatched(AdministrativeRecordTypeCode, ByteBuffer),
}

impl Serialize for AdministrativeRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        match self {
            AdministrativeRecord::BundleStatusReport(sr) => {
                seq.serialize_element(&BUNDLE_STATUS_REPORT_TYPE_CODE)?;
                seq.serialize_element(&sr)?;
            }
            AdministrativeRecord::Unknown(code, data) => {
                seq.serialize_element(&code)?;
                seq.serialize_element(&serde_bytes::Bytes::new(&data))?;
            }
            AdministrativeRecord::Mismatched(code, data) => {
                seq.serialize_element(&code)?;
                seq.serialize_element(&serde_bytes::Bytes::new(&data))?;
            }
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for AdministrativeRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AdministrativeRecordVisitor;

        impl<'de> Visitor<'de> for AdministrativeRecordVisitor {
            type Value = AdministrativeRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("AdministrativeRecord")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let code: AdministrativeRecordTypeCode = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                if code == BUNDLE_STATUS_REPORT_TYPE_CODE {
                    let sr: StatusReport = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    // TODO: check for mixmatched
                    Ok(AdministrativeRecord::BundleStatusReport(sr))
                } else {
                    let data: ByteBuffer = seq
                        .next_element::<serde_bytes::ByteBuf>()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?
                        .into_vec();

                    Ok(AdministrativeRecord::Unknown(code, data))
                }
            }
        }

        deserializer.deserialize_any(AdministrativeRecordVisitor)
    }
}

impl AdministrativeRecord {
    pub fn to_payload(&self) -> crate::canonical::CanonicalBlock {
        let data: ByteBuffer = serde_cbor::to_vec(&self).unwrap();

        crate::canonical::new_payload_block(0, data)
    }
}
// Bundle Status Report

pub type StatusReportReason = u32;

// NO_INFORMATION is the "No additional information" bundle status report reason code.
pub const NO_INFORMATION: StatusReportReason = 0;

// LIFETIME_EXPIRED is the "Lifetime expired" bundle status report reason code.
pub const LIFETIME_EXPIRED: StatusReportReason = 1;

// FORWARD_UNIDIRECTIONAL_LINK is the "Forwarded over unidirectional link" bundle status report reason code.
pub const FORWARD_UNIDIRECTIONAL_LINK: StatusReportReason = 2;

// TRANSMISSION_CANCELED is the "Transmission canceled" bundle status report reason code.
pub const TRANSMISSION_CANCELED: StatusReportReason = 3;

// DEPLETED_STORAGE is the "Depleted storage" bundle status report reason code.
pub const DEPLETED_STORAGE: StatusReportReason = 4;

// DEST_ENDPOINT_UNINTELLIGIBLE is the "Destination endpoint ID unintelligible" bundle status report reason code.
pub const DEST_ENDPOINT_UNINTELLIGIBLE: StatusReportReason = 5;

// NO_ROUTE_TO_DESTINATION is the "No known route to destination from here" bundle status report reason code.
pub const NO_ROUTE_TO_DESTINATION: StatusReportReason = 6;

// NO_NEXT_NODE_CONTACT is the "No timely contact with next node on route" bundle status report reason code.
pub const NO_NEXT_NODE_CONTACT: StatusReportReason = 7;

// BLOCK_UNINTELLIGIBLE is the "Block unintelligible" bundle status report reason code.
pub const BLOCK_UNINTELLIGIBLE: StatusReportReason = 8;

// HOP_LIMIT_EXCEEDED is the "Hop limit exceeded" bundle status report reason code.
pub const HOP_LIMIT_EXCEEDED: StatusReportReason = 9;

// BundleStatusItem represents the a bundle status item, as used as an element
// in the bundle status information array of each Bundle Status Report.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleStatusItem {
    pub asserted: bool,
    pub time: crate::DtnTime,
    pub status_requested: bool,
}

impl Serialize for BundleStatusItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = if self.asserted && self.status_requested {
            2
        } else {
            1
        };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.asserted)?;

        if self.asserted && self.status_requested {
            seq.serialize_element(&self.time)?;
        }
        seq.end()
    }
}
impl<'de> Deserialize<'de> for BundleStatusItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BundleStatusItemVisitor;

        impl<'de> Visitor<'de> for BundleStatusItemVisitor {
            type Value = BundleStatusItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("BundleStatusItem")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let asserted: bool = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let mut status_requested = false;

                let time: crate::DtnTime = if seq.size_hint() == Some(1) {
                    status_requested = true;
                    seq.next_element::<DtnTime>()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?
                } else {
                    0
                };

                Ok(BundleStatusItem {
                    asserted,
                    time,
                    status_requested,
                })
            }
        }

        deserializer.deserialize_any(BundleStatusItemVisitor)
    }
}

// NewBundleStatusItem returns a new BundleStatusItem, indicating an optional
// assertion - givenas asserted -, but no status time request.
fn new_bundle_status_item(asserted: bool) -> BundleStatusItem {
    BundleStatusItem {
        asserted,
        time: crate::dtntime::DTN_TIME_EPOCH,
        status_requested: false,
    }
}

// NewTimeReportingBundleStatusItem returns a new BundleStatusItem, indicating
// both a positive assertion and a requested status time report.
fn new_time_reporting_bundle_status_item(time: DtnTime) -> BundleStatusItem {
    BundleStatusItem {
        asserted: true,
        time,
        status_requested: true,
    }
}

// StatusInformationPos describes the different bundle status information
// entries. Each bundle status report must contain at least the following
// bundle status items.
pub type StatusInformationPos = u32;

// MAX_STATUS_INFORMATION_POS is the amount of different StatusInformationPos.
pub const MAX_STATUS_INFORMATION_POS: u32 = 4;

// RECEIVED_BUNDLE is the first bundle status information entry, indicating the reporting node received this bundle.
pub const RECEIVED_BUNDLE: StatusInformationPos = 0;

// FORWARDED_BUNDLE is the second bundle status information entry, indicating the reporting node forwarded this bundle.
pub const FORWARDED_BUNDLE: StatusInformationPos = 1;

// DELIVERED_BUNDLE is the third bundle status information entry, indicating the reporting node delivered this bundle.
pub const DELIVERED_BUNDLE: StatusInformationPos = 2;

// DELETED_BUNDLE is the fourth bundle status information entry, indicating the reporting node deleted this bundle.
pub const DELETED_BUNDLE: StatusInformationPos = 3;


// StatusReport is the bundle status report, used in an administrative record.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusReport {
    pub status_information: Vec<BundleStatusItem>,
    pub report_reason: StatusReportReason,
    pub source_node: EndpointID,
    pub timestamp: CreationTimestamp,
    pub frag_offset: u64,
    pub frag_len: u64,
}

impl Serialize for StatusReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elems = if self.frag_len != 0 { 6 } else { 4 };

        let mut seq = serializer.serialize_seq(Some(num_elems))?;
        seq.serialize_element(&self.status_information)?;
        seq.serialize_element(&self.report_reason)?;
        seq.serialize_element(&self.source_node)?;
        seq.serialize_element(&self.timestamp)?;
        if num_elems > 4 {
            seq.serialize_element(&self.frag_offset)?;
            seq.serialize_element(&self.frag_len)?;
        }
        seq.end()
    }
}
impl<'de> Deserialize<'de> for StatusReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusReportVisitor;

        impl<'de> Visitor<'de> for StatusReportVisitor {
            type Value = StatusReport;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("StatusReport")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let status_information: Vec<BundleStatusItem> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let report_reason: StatusReportReason = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let source_node: EndpointID = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                let timestamp: CreationTimestamp = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                let mut frag_offset = 0;
                let mut frag_len = 0;

                if seq.size_hint() == Some(2) {
                    frag_offset = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                    frag_len = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(5, &self))?;
                }

                Ok(StatusReport {
                    status_information,
                    report_reason,
                    source_node,
                    timestamp,
                    frag_offset,
                    frag_len,
                })
            }
        }

        deserializer.deserialize_any(StatusReportVisitor)
    }
}

// new_status_report creates a bundle status report for the given bundle and
// StatusInformationPos, which creates the right bundle status item. The
// bundle status report reason code will be used and the bundle status item
// gets the given timestamp.
pub fn new_status_report(
    bndl: &Bundle,
    status_item: StatusInformationPos,
    reason: StatusReportReason,
    time: DtnTime,
) -> StatusReport {
    let mut sr = StatusReport {
        status_information: Vec::new(),
        report_reason: reason,
        source_node: bndl.primary.source.clone(),
        timestamp: bndl.primary.creation_timestamp.clone(),
        frag_offset: 0,
        frag_len: 0,
    };

    if bndl.primary.has_fragmentation() {
        // TODO: add frag code
        unimplemented!();
    }

    for i in 0..MAX_STATUS_INFORMATION_POS {
        if i == status_item
            && bndl
                .primary
                .bundle_control_flags
                .has(BUNDLE_REQUEST_STATUS_TIME)
        {
            sr.status_information
                .push(new_time_reporting_bundle_status_item(time));
        } else if i == status_item {
            sr.status_information.push(new_bundle_status_item(true));
        } else {
            sr.status_information.push(new_bundle_status_item(false));
        }
    }

    sr
}

pub fn new_status_report_bundle(
    orig_bundle: Bundle,
    src: EndpointID,
    crc_type: crc::CRCType,
    status: StatusInformationPos,
    reason: StatusReportReason,
) -> Bundle {
    // TODO: implement sanity checks

    let adm_record = AdministrativeRecord::BundleStatusReport(new_status_report(
        &orig_bundle,
        status,
        reason,
        dtn_time_now(),
    ));

    let pblock = primary::PrimaryBlockBuilder::default()
        .destination(orig_bundle.primary.report_to.clone())
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(CreationTimestamp::now())
        .lifetime(60 * 60 * 1_000_000)
        .build()
        .unwrap();

    let mut b = bundle::BundleBuilder::default()
        .primary(pblock)
        .canonicals(vec![adm_record.to_payload()])
        .build()
        .unwrap();
    b.set_crc(crc_type);

    b
}