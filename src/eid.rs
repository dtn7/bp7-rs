use super::bundle::*;
use core::convert::From;
use core::fmt;
use serde::de::{SeqAccess, Visitor};
//use serde::ser::{SerializeSeq, Serializer};
use serde::{de, Deserialize, Deserializer, Serialize};
use url::Url;

/******************************
 *
 * Endpoint ID
 *
 ******************************/

pub const ENDPOINT_URI_SCHEME_DTN: u8 = 1;
pub const ENDPOINT_URI_SCHEME_IPN: u8 = 2;

pub const DTN_NONE: EndpointID = EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IpnAddress(pub u32, pub u32);

/// # Examples
///
/// ```
/// use bp7::eid::*;
///
/// let cbor_eid = [130, 1, 106, 110, 111, 100, 101, 49, 47, 116, 101, 115, 116];
/// let deserialized: EndpointID = serde_cbor::from_slice(&cbor_eid).unwrap();
/// assert_eq!(deserialized, EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, "node1/test".to_string()))
///
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum EndpointID {
    Dtn(u8, String), // Order of probable occurence, serde tries decoding in untagged enums in this order
    DtnNone(u8, u8),
    Ipn(u8, IpnAddress),
}

/*
// manual implementation not really faster
impl Serialize for EndpointID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        match self {
            EndpointID::Dtn(eid_type, name) => {
                seq.serialize_element(&eid_type)?;
                seq.serialize_element(&name)?;
            }
            EndpointID::DtnNone(eid_type, name) => {
                seq.serialize_element(&eid_type)?;
                seq.serialize_element(&name)?;
            }
            EndpointID::Ipn(eid_type, ipnaddr) => {
                seq.serialize_element(&eid_type)?;
                seq.serialize_element(&ipnaddr)?;
            }
        }

        seq.end()
    }
}*/
impl<'de> Deserialize<'de> for EndpointID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EndpointIDVisitor;

        impl<'de> Visitor<'de> for EndpointIDVisitor {
            type Value = EndpointID;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("EndpointID")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let eid_type: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                if eid_type == ENDPOINT_URI_SCHEME_DTN {
                    // TODO: rewrite to check following type, currently if not string return dtn:none
                    let name: String = seq.next_element().unwrap_or_default().unwrap_or_default();
                    if name == "" {
                        Ok(EndpointID::with_dtn_none())
                    } else {
                        Ok(EndpointID::Dtn(eid_type, name))
                    }
                } else if eid_type == ENDPOINT_URI_SCHEME_IPN {
                    let ipnaddr: IpnAddress = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    Ok(EndpointID::with_ipn(ipnaddr))
                } else {
                    Err(de::Error::invalid_value(
                        de::Unexpected::Unsigned(eid_type.into()),
                        &self,
                    ))
                }
            }
        }

        deserializer.deserialize_any(EndpointIDVisitor)
    }
}

impl Default for EndpointID {
    fn default() -> Self {
        EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0)
    }
}
impl EndpointID {
    pub fn new() -> EndpointID {
        Default::default()
    }
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// assert_eq!(EndpointID::with_dtn("node1"),EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN,"node1".to_string()));
    ///
    /// assert_eq!(EndpointID::with_dtn("node1/endpoint1"),EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN,"node1/endpoint1".to_string()));
    /// ```
    pub fn with_dtn(addr: &str) -> EndpointID {
        EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, addr.into())
    }
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// assert_eq!(EndpointID::with_dtn_none(), EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN,0));
    /// let encoded_eid = serde_cbor::to_vec(&EndpointID::with_dtn_none()).expect("Error serializing packet as cbor.");
    /// println!("{:02x?}", &encoded_eid);
    /// assert_eq!(EndpointID::with_dtn_none(), serde_cbor::from_slice(&encoded_eid).expect("Decoding packet failed"));
    /// ```
    pub fn with_dtn_none() -> EndpointID {
        EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0)
    }
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// assert_eq!(EndpointID::with_ipn( IpnAddress(23, 42) ), EndpointID::Ipn(ENDPOINT_URI_SCHEME_IPN, IpnAddress(23, 42)) );
    ///
    /// let ipn_eid = EndpointID::with_ipn(IpnAddress(23, 42));
    /// let encoded_eid = serde_cbor::to_vec(&ipn_eid).expect("Error serializing packet as cbor.");
    /// println!("{:02x?}", &encoded_eid);
    /// assert_eq!(ipn_eid, serde_cbor::from_slice(&encoded_eid).expect("Decoding packet failed"));
    /// ```
    pub fn with_ipn(addr: IpnAddress) -> EndpointID {
        EndpointID::Ipn(ENDPOINT_URI_SCHEME_IPN, addr)
    }

    pub fn get_scheme(&self) -> String {
        match self {
            EndpointID::DtnNone(_, _) => "dtn".to_string(),
            EndpointID::Dtn(_, _) => "dtn".to_string(),
            EndpointID::Ipn(_, _) => "ipn".to_string(),
        }
    }
    pub fn get_scheme_specific_part_dtn(&self) -> Option<String> {
        match self {
            EndpointID::Dtn(_, ssp) => Some(ssp.to_string()),
            _ => None,
        }
    }
    pub fn to_string(&self) -> String {
        let result = format!(
            "{}://{}",
            self.get_scheme(),
            self.get_scheme_specific_part_dtn()
                .unwrap_or_else(|| "none".to_string())
        );
        result
    }
}

impl fmt::Display for EndpointID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl EndpointID {
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// let eid : EndpointID = "ipn://0.0".to_string().into();
    /// assert_eq!(eid.node_part(),Some("0".to_string()));
    ///
    /// let eid : EndpointID = "dtn://node1/incoming".to_string().into();
    /// assert_eq!(eid.node_part(),Some("node1".to_string()));
    ///
    /// let eid : EndpointID = "dtn://node1".to_string().into();
    /// assert_eq!(eid.node_part(),Some("node1".to_string()));
    /// ```
    pub fn node_part(&self) -> Option<String> {
        match self {
            EndpointID::DtnNone(_, _) => None,
            EndpointID::Dtn(_, eid) => {
                let nodeid: Vec<&str> = eid.split('/').collect();
                Some(nodeid[0].to_string())
            }
            EndpointID::Ipn(_, addr) => Some(addr.0.to_string()),
        }
    }
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// let eid : EndpointID = "ipn://0.0".to_string().into();
    /// assert_eq!(eid.is_node_id(), true);
    ///
    /// let eid : EndpointID = "ipn://0.1".to_string().into();
    /// assert_eq!(eid.is_node_id(), false);
    ///
    /// let eid : EndpointID = "dtn://node1/incoming".to_string().into();
    /// assert_eq!(eid.is_node_id(), false);
    ///
    /// let eid : EndpointID = "dtn://node1".to_string().into();
    /// assert_eq!(eid.is_node_id(), true);
    /// ```
    pub fn is_node_id(&self) -> bool {
        match self {
            EndpointID::DtnNone(_, _) => false,
            EndpointID::Dtn(_, eid) => self.node_part() == Some(eid.to_string()),
            EndpointID::Ipn(_, addr) => addr.1 == 0,
        }
    }

    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// let eid = EndpointID::DtnNone(1, 0);
    /// assert_eq!(eid.validation_error().is_none(), true); // should not fail
    ///
    /// let eid = EndpointID::DtnNone(0, 0);
    /// assert_eq!(eid.validation_error().is_some(), true); // should fail   
    /// let eid = EndpointID::DtnNone(1, 1);
    /// assert_eq!(eid.validation_error().is_some(), true); // should fail   
    ///
    /// let eid = EndpointID::Ipn(2, IpnAddress(23, 42));
    /// assert_eq!(eid.validation_error().is_none(), true); // should not fail
    /// let eid = EndpointID::Ipn(1, IpnAddress(23, 42));
    /// assert_eq!(eid.validation_error().is_some(), true); // should fail   
    /// let eid = EndpointID::Ipn(2, IpnAddress(0, 0));
    /// assert_eq!(eid.validation_error().is_some(), true); // should fail   
    /// ```
    pub fn validation_error(&self) -> Option<Bp7Error> {
        match self {
            EndpointID::Dtn(_, _) => None, // TODO: Implement validation for dtn scheme
            EndpointID::Ipn(code, addr) => {
                if *code != ENDPOINT_URI_SCHEME_IPN {
                    Some(Bp7Error::EIDError(
                        "Wrong URI scheme code for IPN".to_string(),
                    ))
                } else if addr.0 < 1 || addr.1 < 1 {
                    Some(Bp7Error::EIDError(
                        "IPN's node and service number must be >= 1".to_string(),
                    ))
                } else {
                    None
                }
            }
            EndpointID::DtnNone(code, addr) => {
                if *code != ENDPOINT_URI_SCHEME_DTN {
                    Some(Bp7Error::EIDError(
                        "Wrong URI scheme code for DTN".to_string(),
                    ))
                } else if *addr != 0 {
                    Some(Bp7Error::EIDError(
                        "dtn none must have uint(0) set as address".to_string(),
                    ))
                } else {
                    None
                }
            }
        }
    }
}

/// Load EndpointID from URL string.
/// Support for IPN and dtn schemes.
///
/// # Examples
///
/// ```
/// use bp7::eid::*;
///
/// let eid = EndpointID::from("dtn://none".to_string());
/// assert_eq!(eid, EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0));
///
/// let eid = EndpointID::from("dtn:none".to_string());
/// assert_eq!(eid, EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0));
///
/// let eid = EndpointID::from("dtn://node1/endpoint1".to_string());
/// assert_eq!(eid, EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, "node1/endpoint1".to_string()));
///
/// let eid = EndpointID::from("dtn:node1/endpoint1".to_string());
/// assert_eq!(eid, EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, "node1/endpoint1".to_string()));
///   
/// ```
///
/// This should panic:
///
/// ```should_panic
/// use bp7::eid::*;
///
/// let eid = EndpointID::from("node1".to_string());
/// ```
impl From<String> for EndpointID {
    fn from(item: String) -> Self {
        let item = if item.contains("://") {
            item
        } else {
            item.replace(":", "://")
        };
        let u = Url::parse(&item).expect("EndpointID url parsing error");
        let host = u.host_str().expect("EndpointID host parsing error");

        match u.scheme() {
            "dtn" => {
                if host == "none" {
                    return <EndpointID>::with_dtn_none();
                }
                let mut host = format!("{}{}", host, u.path());
                if host.ends_with('/') {
                    host.truncate(host.len() - 1);
                }
                EndpointID::with_dtn(&host)
            }
            "ipn" => {
                let fields: Vec<&str> = host.split('.').collect();
                if fields.len() != 2 {
                    panic!("wrong number of fields in IPN address");
                }
                let p1: u32 = fields[0].parse().unwrap();
                let p2: u32 = fields[1].parse().unwrap();

                EndpointID::with_ipn(IpnAddress(p1, p2))
            }
            _ => <EndpointID>::with_dtn_none(),
        }
    }
}

impl From<&str> for EndpointID {
    fn from(item: &str) -> Self {
        EndpointID::from(String::from(item))
    }
}
