use alloc::{string::{String, ToString}, vec::Vec};
use casper_types::{ContractHash, U512, CLTyped, CLType, bytesrepr::{FromBytes, ToBytes, self}, Key, U256};

use crate::external::xp_nft::TokenIdentifier;


#[derive(Clone)]
pub struct FreezeNFT {
    pub contract: ContractHash,
    pub token_id: TokenIdentifier,
    pub to: String,
    pub mint_with: String,
    pub chain_nonce: u8,
    pub amt: U512,
    pub sig_data: [u8; 64],
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


pub struct TxFee {
    pub value: U512,
    pub from: u8,
    pub to: u8,
    pub receiver: String,
}

impl ToBytes for TxFee {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.value.to_bytes()?);
        result.extend(self.from.to_bytes()?);
        result.extend(self.to.to_bytes()?);
        result.extend(self.receiver.to_bytes()?);

        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.value.serialized_length()
            + self.from.serialized_length()
            + self.to.serialized_length()
            + self.receiver.serialized_length()
    }
}



#[derive(Clone)]
pub struct ValidateUnfreezeData {
    pub contract: ContractHash,
    pub token_id: TokenIdentifier,
    pub receiver: Key,
    pub action_id: U256,
}

impl FromBytes for ValidateUnfreezeData {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (contract, remainder) = ContractHash::from_bytes(bytes)?;
        let (receiver, remainder) = Key::from_bytes(remainder)?;
        let (token_id, remainder) = TokenIdentifier::from_bytes(remainder)?;
        let (action_id, remainder) = U256::from_bytes(remainder)?;
        Ok((
            Self {
                token_id,
                receiver,
                action_id,
                contract,
            },
            remainder,
        ))
    }
}

impl ToBytes for ValidateUnfreezeData {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.contract.to_bytes()?);
        result.extend(self.receiver.to_bytes()?);
        result.extend(self.token_id.to_bytes()?);
        result.extend(self.action_id.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_id.serialized_length()
            + self.contract.serialized_length()
            + self.token_id.serialized_length()
            + self.receiver.serialized_length()
    }
}