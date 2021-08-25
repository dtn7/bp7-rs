use core::fmt;

use thiserror::Error;

use crate::eid::EndpointIdError;

#[derive(Debug, Error)]
pub enum Error {
    CanonicalBlockError(String),
    PrimaryBlockError(String),
    EIDError(#[from] EndpointIdError),
    DtnTimeError(String),
    CrcError(String),
    BundleError(String),
    BundleControlFlagsError(String),
    BlockControlFlagsError(String),
    JsonDecodeError(#[from] serde_json::Error),
    CborDecodeError(#[from] serde_cbor::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

pub type ErrorList = Vec<Error>;
