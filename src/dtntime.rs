use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use humantime::format_rfc3339;
#[cfg(feature = "mini")]
use minicbor::{decode, encode, Decode, Decoder, Encode, Encoder};
#[cfg(feature = "cbor_serde")]
use serde::{Deserialize, Serialize};
use std::time::UNIX_EPOCH;

/// Time since the year 2k in milliseconds
pub type DtnTime = u64;

pub const SECONDS1970_TO2K: u64 = 946_684_800;
const MS1970_TO2K: u64 = 946_684_800_000;

pub const DTN_TIME_EPOCH: DtnTime = 0;

pub trait DtnTimeHelpers {
    fn unix(self) -> u64;
    fn string(self) -> String;
}

impl DtnTimeHelpers for DtnTime {
    /// Convert to unix timestamp (in seconds).
    fn unix(self) -> u64 {
        ((self + MS1970_TO2K) / 1000) as u64
    }

    /// Convert to human readable rfc3339 compliant time string.
    fn string(self) -> String {
        let d = UNIX_EPOCH + Duration::from_millis(self + MS1970_TO2K);
        format_rfc3339(d).to_string()
    }
}

/// Get current time as DtnTime timestamp
pub fn dtn_time_now() -> DtnTime {
    crate::helpers::ts_ms() - MS1970_TO2K
}

/// Timestamp when a bundle was created, consisting of the DtnTime and a sequence number.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)] // hacked struct as tuple because bug in serialize_tuple
pub struct CreationTimestamp(DtnTime, u64);

#[cfg(feature = "mini")]
impl encode::Encode for CreationTimestamp {
    fn encode<W: encode::Write>(&self, e: &mut Encoder<W>) -> Result<(), encode::Error<W::Error>> {
        e.array(2)?.u64(self.0)?.u64(self.1)?.ok()
    }
}
#[cfg(feature = "mini")]
impl<'b> Decode<'b> for CreationTimestamp {
    fn decode(d: &mut Decoder<'b>) -> Result<Self, decode::Error> {
        if let Some(2) = d.array()? {
            Ok(CreationTimestamp(d.u64()?, d.u64()?))
        } else {
            Err(minicbor::decode::Error::Message("invalid array length"))
        }
    }
}
impl fmt::Display for CreationTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.0.string(), self.1)
    }
}

impl CreationTimestamp {
    pub fn new() -> CreationTimestamp {
        Default::default()
    }
    pub fn with_time_and_seq(t: DtnTime, seqno: u64) -> CreationTimestamp {
        CreationTimestamp(t, seqno)
    }
    pub fn seqno(&self) -> u64 {
        self.1
    }
    pub fn dtntime(&self) -> DtnTime {
        self.0
    }
    /// Create a new timestamp with automatic sequence counting
    ///
    /// # Example
    /// ```
    /// use bp7::dtntime::*;
    /// use std::{thread, time};
    ///
    /// let time1 = CreationTimestamp::now();
    /// let time2 = CreationTimestamp::now();
    ///
    /// assert_eq!(time1.dtntime(), time2.dtntime());
    /// assert_ne!(time1.seqno(), time2.seqno());
    ///
    /// thread::sleep(time::Duration::from_secs(1));
    /// let time3 = CreationTimestamp::now();
    /// assert_eq!(time3.seqno(), 0);
    /// ```
    pub fn now() -> CreationTimestamp {
        static LAST_CREATION_TIMESTAMP: AtomicUsize = AtomicUsize::new(0);
        static LAST_CREATION_SEQ: AtomicUsize = AtomicUsize::new(0);
        let now = dtn_time_now();
        if now != LAST_CREATION_TIMESTAMP.swap(now as usize, Ordering::Relaxed) as u64 {
            LAST_CREATION_SEQ.store(0, Ordering::SeqCst)
        }
        let seq = LAST_CREATION_SEQ.fetch_add(1, Ordering::SeqCst);

        CreationTimestamp::with_time_and_seq(now, seq as u64)
    }
}
