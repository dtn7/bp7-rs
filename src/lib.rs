//! Rust implementation of [dtn bundle protocol 7 draft](https://tools.ietf.org/html/draft-ietf-dtn-bpbis-12)
//!
//! # Examples
//!
//! ```
//! use bp7::{bundle, canonical, crc, dtntime, eid, primary};
//! use std::time::Duration;
//!
//! let dst = eid::EndpointID::with_dtn("node2/inbox").unwrap();
//! let src = eid::EndpointID::with_dtn("node1/123456").unwrap();
//! //let now = dtntime::CreationTimestamp::now();
//! let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);
//! let pblock = primary::PrimaryBlockBuilder::default()
//!     .bundle_control_flags(
//!         bundle::BUNDLE_MUST_NOT_FRAGMENTED | bundle::BUNDLE_STATUS_REQUEST_DELIVERY,
//!     )
//!     .destination(dst)
//!     .source(src.clone())
//!     .report_to(src)
//!     .creation_timestamp(day0)
//!     .lifetime(Duration::from_secs(60 * 60))
//!     .build()
//!     .unwrap();
//! let mut b = bundle::BundleBuilder::default()
//!     .primary(pblock)
//!     .canonicals(vec![canonical::new_payload_block(0, b"ABC".to_vec())])
//!     .build()
//!     .unwrap();
//! b.set_crc(crc::CRC_16);
//! let serialized = b.to_cbor();
//! let binary_bundle = [159, 137, 7, 26, 0, 2, 0, 4, 1, 130, 1, 107, 110, 111, 100, 101,
//!     50, 47, 105, 110, 98, 111, 120, 130, 1, 108, 110, 111, 100, 101, 49, 47, 49, 50,
//!     51, 52, 53, 54, 130, 1, 108, 110, 111, 100, 101, 49, 47, 49, 50, 51, 52, 53, 54,
//!     130, 0, 0, 26, 0, 54, 238, 128, 66, 200, 148, 134, 1, 1, 0, 1, 68, 67, 65, 66,
//!     67, 66, 196, 61, 255];
//! assert_eq!(&binary_bundle[..], &serialized[..]);
//! ```
//!
//!

#![forbid(unsafe_code)]

pub mod administrative_record;
pub mod bundle;
pub mod canonical;
pub mod crc;
pub mod dtntime;
pub mod eid;
pub mod helpers;
pub mod primary;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use bundle::{Bp7Error, Bp7ErrorList, Bundle, ByteBuffer};
pub use canonical::*;
pub use dtntime::{dtn_time_now, CreationTimestamp, DtnTime};
pub use eid::EndpointID;
pub use helpers::hexify;

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
