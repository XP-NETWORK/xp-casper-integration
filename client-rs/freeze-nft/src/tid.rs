use alloc::string::{String, ToString};
use casper_types::{
    bytesrepr::{FromBytes, ToBytes},
    CLType, CLTyped,
};

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum TokenIdentifier {
    Index(u64),
    Hash(String),
}

impl CLTyped for TokenIdentifier {
    fn cl_type() -> casper_types::CLType {
        CLType::String
    }
}

impl FromBytes for TokenIdentifier {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (tid, remainder) = String::from_bytes(bytes)?;
        match tid.parse::<u64>() {
            Ok(e) => Ok((TokenIdentifier::Index(e), remainder)),
            Err(_) => Ok((TokenIdentifier::Hash(tid), remainder)),
        }
    }
}
impl ToBytes for TokenIdentifier {
    fn to_bytes(&self) -> Result<alloc::vec::Vec<u8>, casper_types::bytesrepr::Error> {
        match self {
            TokenIdentifier::Index(index) => index.to_string().to_bytes(),
            TokenIdentifier::Hash(hash) => hash.to_bytes(),
        }
    }

    fn serialized_length(&self) -> usize {
        match self {
            TokenIdentifier::Index(e) => e.to_string().serialized_length(),
            TokenIdentifier::Hash(h) => h.serialized_length(),
        }
    }
}
