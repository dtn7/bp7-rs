use crate::{bundle, dtntime, eid};
use core::num::ParseIntError;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_arch = "wasm32"))]
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
pub fn unix_timestamp() -> u64 {
    (stdweb::web::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn ts_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards!!")
        .as_millis()
}

#[cfg(target_arch = "wasm32")]
pub fn ts_ms() -> u128 {
    (stdweb::web::Date::now()) as u128
}

/// Convert byte slice into a hex string
pub fn hexify(buf: &[u8]) -> String {
    let mut hexstr = String::new();
    for &b in buf {
        hexstr.push_str(&format!("{:02x?}", b));
    }
    hexstr
}
/// Convert a hex string into a byte vector
pub fn unhexify(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn rnd_bundle(now: dtntime::CreationTimestamp) -> bundle::Bundle {
    let mut rng = rand::thread_rng();
    let dst_string = format!("node{}/inbox", rng.gen_range(1, 4));
    let src_string = format!("node{}/inbox", rng.gen_range(1, 4));
    let dst = eid::EndpointID::with_dtn(&dst_string).unwrap();
    let src = eid::EndpointID::with_dtn(&src_string).unwrap();
    //let now = dtntime::CreationTimestamp::with_time_and_seq(dtntime::dtn_time_now(), 0);;
    //let day0 = dtntime::CreationTimestamp::with_time_and_seq(dtntime::DTN_TIME_EPOCH, 0);;
    let mut b = bundle::new_std_payload_bundle(src, dst, b"ABC".to_vec());
    b.primary.creation_timestamp = now;
    b
}

pub struct Url {
    scheme: String,
    host: String,
    path: String,
    query: String,
}

impl Url {
    pub fn parse(raw_url: &str) -> Result<Self, &'static str> {
        let fields: Vec<&str> = raw_url.split("://").collect();
        if fields.len() != 2 {
            return Err("Error parsing url: scheme missing");
        }
        let scheme = String::from(fields[0]);
        let blocks: Vec<&str> = fields[1].split('?').collect();
        let mut query = String::new();

        if blocks.len() > 2 {
            return Err("Error parsing url: too many '?' in url");
        } else if blocks.len() == 2 {
            query = String::from(blocks[1]);
        }
        let uri: Vec<&str> = blocks[0].split('/').collect();
        let mut path = String::new();
        if uri.is_empty() {
            return Err("Error parsing url: host missing");
        } else {
        }
        let host = String::from(uri[0]);
        if uri.len() > 1 {
            path = String::from("/") + &uri[1..].join("/");
        }

        Ok(Url {
            scheme,
            host,
            path,
            query,
        })
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn query(&self) -> &str {
        &self.query
    }
}
