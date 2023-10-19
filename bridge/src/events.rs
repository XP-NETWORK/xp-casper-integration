use alloc::string::{String, ToString};
use casper_event_standard::Event;
use casper_types::{
    bytesrepr::{FromBytes, ToBytes},
    CLType, CLTyped, U512,
};

use crate::external::xp_nft::TokenIdentifier;

#[derive(Clone, Event, Debug)]
pub struct TransferNftEvent {
    pub chain_nonce: u8,
    pub to: String,
    pub mint_with: String,
    pub amt: U512,
    pub token_id: TokenIdentifier,
    pub contract: String,
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

#[derive(Clone, Event, Debug)]
pub struct UnfreezeNftEvent {
    pub chain_nonce: u8,
    pub to: String,
    pub amt: U512,
    pub token_id: TokenIdentifier,
    pub contract: String,
}
