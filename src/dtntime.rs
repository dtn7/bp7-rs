use chrono::prelude::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type DtnTime = u64;

pub const SECONDS1970_TO2K: u64 = 946_684_800;
pub const DTN_TIME_EPOCH: DtnTime = 0;

pub trait DtnTimeHelpers {
    fn unix(self) -> u64;
    fn string(self) -> String;
}

impl DtnTimeHelpers for DtnTime {
    /// Convert to unix timestamp.
    fn unix(self) -> u64 {
        self + SECONDS1970_TO2K
    }

    /// Convert to human readable rfc3339 compliant time string.
    fn string(self) -> String {
        let d = UNIX_EPOCH + Duration::from_secs(self + SECONDS1970_TO2K);
        let datetime = DateTime::<Utc>::from(d);
        datetime.to_rfc3339()
    }
}

/// Get current time as DtnTime timestamp
pub fn dtn_time_now() -> DtnTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_secs()
        - SECONDS1970_TO2K
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
    pub fn get_seqno(&self) -> u64 {
        self.1
    }
    pub fn get_dtntime(&self) -> DtnTime {
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
    /// assert_eq!(time1.get_dtntime(), time2.get_dtntime());
    /// assert_ne!(time1.get_seqno(), time2.get_seqno());
    ///
    /// thread::sleep(time::Duration::from_secs(1));
    /// let time3 = CreationTimestamp::now();
    /// assert_eq!(time3.get_seqno(), 0);
    /// ```
    pub fn now() -> CreationTimestamp {
        let now = dtn_time_now();
        if now != LAST_CREATION_TIMESTAMP.swap(now as usize, Ordering::Relaxed) as u64 {
            LAST_CREATION_SEQ.store(0, Ordering::SeqCst)
        }
        let seq = LAST_CREATION_SEQ.fetch_add(1, Ordering::SeqCst);

        CreationTimestamp::with_time_and_seq(now, seq as u64)
    }
}

static LAST_CREATION_TIMESTAMP: AtomicUsize = AtomicUsize::new(0);
static LAST_CREATION_SEQ: AtomicUsize = AtomicUsize::new(0);
