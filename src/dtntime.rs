use core::fmt;
use core::time::Duration;
use humantime::format_rfc3339;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
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
        (self + MS1970_TO2K) / 1000
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
        // time and sequence number are updated together to stay unique across threads
        static LAST_CREATION: Mutex<(DtnTime, u64)> = Mutex::new((0, 0));
        let mut last = LAST_CREATION.lock().unwrap_or_else(|e| e.into_inner());
        let now = dtn_time_now();
        if now != last.0 {
            *last = (now, 0);
        }
        let seq = last.1;
        last.1 += 1;

        CreationTimestamp::with_time_and_seq(now, seq)
    }
}
