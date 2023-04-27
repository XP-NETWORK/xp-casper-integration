use alloc::{string::String, vec::Vec};
use casper_types::{
    account::AccountHash,
    bytesrepr::{self, FromBytes, ToBytes},
    ContractHash, Key, U128, U256, U512,
};

use crate::external::xp_nft::TokenIdentifier;

pub struct PauseData {
    pub action_id: U256,
}

impl FromBytes for PauseData {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_id, remainder) = U256::from_bytes(bytes)?;
        Ok((Self { action_id }, remainder))
    }
}

impl ToBytes for PauseData {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.action_id.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_id.serialized_length()
    }
}

pub struct UnpauseData {
    pub action_id: U256,
}

impl FromBytes for UnpauseData {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_id, remainder) = U256::from_bytes(bytes)?;
        Ok((Self { action_id }, remainder))
    }
}

impl ToBytes for UnpauseData {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.action_id.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_id.serialized_length()
    }
}

#[derive(Clone)]
pub struct ValidateTransferData {
    pub mint_with: ContractHash,
    pub receiver: Key,
    pub metadata: String,
    pub action_id: U256,
}

impl FromBytes for ValidateTransferData {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (mint_with, remainder) = ContractHash::from_bytes(bytes)?;
        let (receiver, remainder) = Key::from_bytes(remainder)?;
        let (metadata, remainder) = String::from_bytes(remainder)?;
        let (action_id, remainder) = U256::from_bytes(remainder)?;
        Ok((
            Self {
                mint_with,
                receiver,
                action_id,
                metadata,
            },
            remainder,
        ))
    }
}

impl ToBytes for ValidateTransferData {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        todo!()
    }

    fn serialized_length(&self) -> usize {
        todo!()
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
        let token_id = TokenIdentifier::Index(1);
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
        todo!()
    }

    fn serialized_length(&self) -> usize {
        todo!()
    }
}

#[derive(Clone)]
pub struct FreezeNFT {
    pub contract: ContractHash,
    pub token_id: TokenIdentifier,
    pub to: String,
    pub mint_with: String,
    pub chain_nonce: u8,
    pub amt: U512,
    pub sig_data: Vec<u8>,
}

impl FromBytes for FreezeNFT {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (contract, remainder) = ContractHash::from_bytes(bytes)?;
        let (to, remainder) = String::from_bytes(remainder)?;
        let token_id = TokenIdentifier::Index(1);
        let (mint_with, remainder) = String::from_bytes(remainder)?;
        let (sig_data, remainder) = Vec::from_bytes(remainder)?;
        let (chain_nonce, remainder) = u8::from_bytes(remainder)?;
        let (amt, remainder) = U512::from_bytes(remainder)?;
        Ok((
            Self {
                token_id,
                to,
                mint_with,
                contract,
                sig_data,
                chain_nonce,
                amt,
            },
            remainder,
        ))
    }
}

impl ToBytes for FreezeNFT {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        todo!()
    }

    fn serialized_length(&self) -> usize {
        todo!()
    }
}

#[derive(Clone)]
pub struct WithdrawNFT {
    pub token_id: TokenIdentifier,
    pub to: String,
    pub chain_nonce: u8,
    pub contract: ContractHash,
    pub amt: U512,
    pub sig_data: Vec<u8>,
}

impl FromBytes for WithdrawNFT {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (contract, remainder) = ContractHash::from_bytes(bytes)?;
        let (to, remainder) = String::from_bytes(remainder)?;
        let token_id = TokenIdentifier::Index(1);
        let (sig_data, remainder) = Vec::from_bytes(remainder)?;
        let (chain_nonce, remainder) = u8::from_bytes(remainder)?;
        let (amt, remainder) = U512::from_bytes(remainder)?;
        Ok((
            Self {
                token_id,
                to,
                contract,
                sig_data,
                chain_nonce,
                amt,
            },
            remainder,
        ))
    }
}

impl ToBytes for WithdrawNFT {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        todo!()
    }

    fn serialized_length(&self) -> usize {
        todo!()
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
        todo!()
    }

    fn serialized_length(&self) -> usize {
        todo!()
    }
}
#[derive(Clone)]
pub struct UpdateGroupKey {
    pub action_id: U256,
    pub new_key: Vec<u8>,
}

impl FromBytes for UpdateGroupKey {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_id, remainder) = U256::from_bytes(bytes)?;
        let (new_key, remainder) = Vec::from_bytes(bytes)?;
        Ok((Self { action_id, new_key }, remainder))
    }
}

impl ToBytes for UpdateGroupKey {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.action_id.to_bytes()?);
        result.extend(self.new_key.to_vec());
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_id.serialized_length() + self.new_key.serialized_length()
    }
}
