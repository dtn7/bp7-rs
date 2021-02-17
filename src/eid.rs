use core::convert::From;
use core::fmt;
use serde::de::{SeqAccess, Visitor};
//use serde::ser::{SerializeSeq, Serializer};
use crate::helpers::{to_vec, Url};
use core::convert::TryFrom;
use core::convert::TryInto;
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

/******************************
 *
 * Endpoint ID
 *
 ******************************/

const ENDPOINT_URI_SCHEME_DTN: u8 = 1;
const ENDPOINT_URI_SCHEME_IPN: u8 = 2;

#[deprecated(note = "Please use EndpointID::none() instead")]
pub const DTN_NONE: EndpointID = EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IpnAddress(u64, u64);

impl IpnAddress {
    pub fn new(node: u64, service: u64) -> IpnAddress {
        IpnAddress(node, service)
    }
    pub fn node_number(&self) -> u64 {
        self.0
    }
    pub fn service_number(&self) -> u64 {
        self.1
    }
}
impl fmt::Display for IpnAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum EndpointIdError {
    #[error("scheme not found")]
    SchemeMissing,
    #[error("scheme not matching, found `{0}` expected `{1}`")]
    SchemeMismatch(u8, u8),
    #[error("unknown address scheme `{0}`")]
    UnknownScheme(String),
    #[error("invalid node number `{0}` for ipn address")]
    InvalidNodeNumber(u64),
    #[error("wrong number of fields for ipn address, found `{0}` expected `2`")]
    WrongNumberOfFieldsInIpn(u64),
    #[error("invalid service endpoint `{0}`")]
    InvalidService(String),
    #[error("none endpoint can not have a service")]
    NoneHasNoService,
    #[error("none endpoint must have service number 0")]
    NoneNotZero,
    #[error("malformed address url")]
    InvalidUrlFormat,
    #[error("unknown endpoint id error")]
    Unknown,
}
/// Represents an endpoint in various addressing schemes.
///
/// Either the *none* endpoint, a dtn one or an ipn endpoint.
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
                        Ok(EndpointID::none())
                    } else {
                        Ok(EndpointID::Dtn(eid_type, name))
                    }
                } else if eid_type == ENDPOINT_URI_SCHEME_IPN {
                    let ipnaddr: IpnAddress = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    if let Ok(ipn) = ipnaddr.try_into() {
                        // Conversion can fail as validation happens within function
                        Ok(ipn)
                    } else {
                        Err(de::Error::invalid_value(
                            de::Unexpected::StructVariant,
                            &self,
                        ))
                    }
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
    /// Default returns a `dtn:none` endpoint
    pub fn new() -> EndpointID {
        Default::default()
    }
    /// Create a new EndpointID with dtn addressing scheme
    ///
    /// This can either be a host id such as `dtn://node1` or
    /// include an application agents endpoint, e.g., `dtn://node1/endpoint1`
    pub fn with_dtn(host_with_endpoint: &str) -> Result<EndpointID, EndpointIdError> {
        let eid = EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, host_with_endpoint.to_owned());
        if let Err(err) = eid.validate() {
            Err(err)
        } else {
            Ok(eid)
        }
    }
    /// Create a new 'dtn:none' endpoint
    ///
    /// This is the same as `DTN_NONE`    
    pub const fn none() -> EndpointID {
        EndpointID::DtnNone(ENDPOINT_URI_SCHEME_DTN, 0)
    }

    /// Create a new EndpointID with ipn addressing scheme
    ///
    /// This can either be a host id such as 'ipn://23.0' or
    /// include an application agents endpoint, e.g., 'ipn://23.42'
    ///
    /// **host must be > 0**
    pub fn with_ipn(host: u64, endpoint: u64) -> Result<EndpointID, EndpointIdError> {
        let addr = IpnAddress::new(host, endpoint);
        let eid = EndpointID::Ipn(ENDPOINT_URI_SCHEME_IPN, addr);
        if let Err(err) = eid.validate() {
            Err(err)
        } else {
            Ok(eid)
        }
    }

    /// Generate a new Endpoint ID from existing one with a specific service endpoint
    ///
    /// Keeps scheme and host specific parts from original eid.
    ///
    /// # Examples
    ///
    /// ```
    /// use bp7::eid::*;
    ///
    /// // For ipn addresses
    ///
    /// let ipn_addr_1 = EndpointID::with_ipn(23, 42).unwrap();
    /// let ipn_addr_2 = EndpointID::with_ipn(23, 7).unwrap();
    ///
    /// assert_eq!(ipn_addr_1, ipn_addr_2.new_endpoint("42").unwrap());
    ///
    /// let ipn_addr_1 = EndpointID::with_ipn(23, 42).unwrap();    
    ///
    /// assert!(ipn_addr_1.new_endpoint("-42").is_err());    
    ///
    /// // For dtn addresses
    /// let dtn_addr_1 = EndpointID::with_dtn( "node1/incoming").unwrap();
    /// let dtn_addr_2 = EndpointID::with_dtn( "node1/inbox").unwrap();
    ///
    /// assert_eq!(dtn_addr_1, dtn_addr_2.new_endpoint("incoming").unwrap());
    ///
    /// // For non endpoint this is not possible
    ///
    /// let dtn_addr_none = EndpointID::none();    
    ///
    /// assert!(dtn_addr_none.new_endpoint("incoming").is_err());    
    ///    
    /// ```
    pub fn new_endpoint(&self, ep: &str) -> Result<EndpointID, EndpointIdError> {
        match self {
            EndpointID::DtnNone(_, _) => Err(EndpointIdError::NoneHasNoService),
            EndpointID::Dtn(_, _) => format!("dtn://{}/{}", self.node().unwrap(), ep).try_into(),
            EndpointID::Ipn(_, ipnaddr) => {
                if let Ok(number) = ep.trim().parse::<u64>() {
                    EndpointID::with_ipn(ipnaddr.node_number(), number)
                } else {
                    Err(EndpointIdError::InvalidService(ep.to_owned()))
                }
            }
        }
    }

    pub fn scheme(&self) -> String {
        match self {
            EndpointID::DtnNone(_, _) => "dtn".to_string(),
            EndpointID::Dtn(_, _) => "dtn".to_string(),
            EndpointID::Ipn(_, _) => "ipn".to_string(),
        }
    }
    pub fn scheme_specific_part_dtn(&self) -> Option<String> {
        match self {
            EndpointID::Dtn(_, ssp) => Some(ssp.to_string()),
            _ => None,
        }
    }
    pub fn scheme_specific_part_ipn(&self) -> Option<IpnAddress> {
        match self {
            EndpointID::Ipn(_, ssp) => Some(ssp.to_owned()),
            _ => None,
        }
    }
}

impl fmt::Display for EndpointID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr = match self {
            EndpointID::Ipn(_, ssp) => ssp.to_string(),
            EndpointID::Dtn(_, ssp) => ssp.to_string(),
            _ => "none".to_string(),
        };
        write!(f, "{}://{}", self.scheme(), addr)
    }
}

impl EndpointID {
    /// Returns the plain node name without URL scheme
    pub fn node(&self) -> Option<String> {
        match self {
            EndpointID::DtnNone(_, _) => None,
            EndpointID::Dtn(_, eid) => {
                let nodeid: Vec<&str> = eid.split('/').collect();
                Some(nodeid[0].to_string())
            }
            EndpointID::Ipn(_, addr) => Some(addr.node_number().to_string()),
        }
    }
    /// Returns the node name including URL scheme
    pub fn node_id(&self) -> Option<String> {
        match self {
            EndpointID::DtnNone(_, _) => None,
            _ => Some(format!("{}://{}", self.scheme(), self.node()?)),
        }
    }

    pub fn is_node_id(&self) -> bool {
        match self {
            EndpointID::DtnNone(_, _) => false,
            EndpointID::Dtn(_, eid) => self.node() == Some(eid.to_string()),
            EndpointID::Ipn(_, addr) => addr.1 == 0,
        }
    }

    pub fn validate(&self) -> Result<(), EndpointIdError> {
        match self {
            EndpointID::Dtn(_, _) => Ok(()), // TODO: Implement validation for dtn scheme
            EndpointID::Ipn(code, addr) => {
                if *code != ENDPOINT_URI_SCHEME_IPN {
                    Err(EndpointIdError::SchemeMismatch(
                        *code,
                        ENDPOINT_URI_SCHEME_IPN,
                    ))
                } else if addr.node_number() < 1 {
                    Err(EndpointIdError::InvalidNodeNumber(addr.node_number()))
                } else {
                    Ok(())
                }
            }
            EndpointID::DtnNone(code, addr) => {
                if *code != ENDPOINT_URI_SCHEME_DTN {
                    Err(EndpointIdError::SchemeMismatch(
                        *code,
                        ENDPOINT_URI_SCHEME_DTN,
                    ))
                } else if *addr != 0 {
                    Err(EndpointIdError::NoneNotZero)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Load EndpointID from URL string.
///
/// Support for ipn and dtn schemes.
impl TryFrom<String> for EndpointID {
    type Error = EndpointIdError;
    fn try_from(item: String) -> Result<Self, Self::Error> {
        let item = if item.contains("://") {
            item
        } else {
            item.replace(":", "://")
        };
        let u = Url::parse(&item).map_err(|_| EndpointIdError::SchemeMissing)?;
        let host = u.host();

        match u.scheme() {
            "dtn" => {
                if host == "none" {
                    return Ok(<EndpointID>::none());
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
                let p1: u64 = fields[0].parse().unwrap();
                let p2: u64 = fields[1].parse().unwrap();

                EndpointID::with_ipn(p1, p2)
            }
            _ => Ok(<EndpointID>::none()),
        }
    }
}

impl TryFrom<&str> for EndpointID {
    type Error = EndpointIdError;
    fn try_from(item: &str) -> Result<Self, Self::Error> {
        EndpointID::try_from(String::from(item))
    }
}
impl TryFrom<IpnAddress> for EndpointID {
    type Error = EndpointIdError;
    fn try_from(item: IpnAddress) -> Result<Self, Self::Error> {
        EndpointID::with_ipn(item.node_number(), item.service_number())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use crate::helpers::from_slice;

    use super::*;
    use test_case::test_case;

    #[test_case("node1")]
    #[test_case("node1/incoming")]
    fn create_with_dtn_tests(input: &str) {
        assert_eq!(
            EndpointID::with_dtn(input).unwrap(),
            EndpointID::Dtn(ENDPOINT_URI_SCHEME_DTN, input.to_string())
        );
    }

    #[test_case("dtn://n1/incoming" => "dtn://n1/incoming" ; "when using fully qualified dtn endpoint")]
    #[test_case("dtn://n1/incoming/" => "dtn://n1/incoming" ; "when containing tail slash")]
    #[test_case("dtn://n1/" => "dtn://n1" ; "when providing node eid")]
    #[test_case("dtn:n1/incoming" => "dtn://n1/incoming" ; "when skipping double slash for dtn")]
    #[test_case("dtn//n1/incoming" => panics "" ; "when missing URL scheme separator")]
    #[test_case("n1/incoming" => panics "" ; "when missing URL scheme")]
    #[test_case("ipn://23.42" => "ipn://23.42" ; "when using valid ipn endpoint")]
    #[test_case("ipn://23.0" => "ipn://23.0" ; "when using service number 0")]
    #[test_case("ipn:23.42" => "ipn://23.42" ; "when skipping double slash for ipn")]
    #[test_case("ipn://23.data" => panics "" ; "when providing string as service number in ipn")]
    #[test_case("ipn://0.42" => panics "" ; "when using node number 0 in ipn")]
    #[test_case("dtn://none" => "dtn://none" ; "when using none endpoint")]
    #[test_case("dtn:n1/" => "dtn://n1" ; "when using none endpoint without double slash")]
    #[test_case("dtn://none" => EndpointID::none().to_string() ; "when providing node eid and constructed none")]
    fn from_str_tests(input_str: &str) -> String {
        EndpointID::try_from(input_str).unwrap().to_string()
    }

    #[test_case(EndpointID::DtnNone(1, 0) => true)]
    #[test_case(EndpointID::DtnNone(0, 0) => false)]
    #[test_case(EndpointID::DtnNone(1, 1) => false)]
    #[test_case(EndpointID::Ipn(ENDPOINT_URI_SCHEME_IPN, IpnAddress::new(23, 42)) => true)]
    #[test_case(EndpointID::Ipn(ENDPOINT_URI_SCHEME_DTN, IpnAddress::new(23, 42)) => false)]
    #[test_case(EndpointID::Ipn(ENDPOINT_URI_SCHEME_IPN, IpnAddress::new(0, 0)) => false)]
    fn validate_test(eid: EndpointID) -> bool {
        eid.validate().is_ok()
    }
    #[test_case("ipn://1.0".try_into().unwrap() => true ; "when providing ipn node id")]
    #[test_case("ipn://1.1".try_into().unwrap() => false ; "when providing full ipn address")]
    #[test_case("dtn://node1".try_into().unwrap() => true ; "when providing dtn node id")]
    #[test_case("dtn://node1/incoming".try_into().unwrap() => false ; "when providing full dtn address")]
    #[test_case("dtn://none".try_into().unwrap() => false ; "when providing none endpoint")]
    fn is_node_id_tests(eid: EndpointID) -> bool {
        eid.is_node_id()
    }

    #[test_case("ipn://1.0".try_into().unwrap() => Some("1".to_string()))]
    #[test_case("dtn://node1/incoming".try_into().unwrap() => Some("node1".to_string()))]
    #[test_case("dtn://node1".try_into().unwrap() => Some("node1".to_string()))]
    fn node_part_tests(eid: EndpointID) -> Option<String> {
        eid.node()
    }
    #[test_case("dtn://none".try_into().unwrap() ; "when using none endpoint")]
    #[test_case("ipn://23.42".try_into().unwrap() ; "when using ipn address")]
    #[test_case("dtn://node1/incoming".try_into().unwrap() ; "when using dtn address")]

    fn serialize_deserialize_tests(eid: EndpointID) {
        let encoded_eid = to_vec(&eid).expect("Error serializing packet as cbor.");
        println!("{:02x?}", &encoded_eid);
        assert_eq!(
            eid,
            from_slice(&encoded_eid).expect("Decoding packet failed")
        );
    }

    #[test_case(&[130, 1, 106, 110, 111, 100, 101, 49, 47, 116, 101, 115, 116] => "dtn://node1/test"; "when decoding full dtn address")]
    fn test_ser_eid(cbor_eid: &[u8]) -> String {
        let deserialized: EndpointID = from_slice(cbor_eid).unwrap();
        deserialized.to_string()
    }
}
