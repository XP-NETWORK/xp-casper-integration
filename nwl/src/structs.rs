use alloc::vec::Vec;
use casper_types::{
    account::AccountHash,
    bytesrepr::{self, FromBytes, ToBytes},
    ContractHash, U256,
};

#[derive(Clone)]
pub struct UpdateGroupKey {
    pub action_id: U256,
    pub new_key: Vec<u8>,
}

impl FromBytes for UpdateGroupKey {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_id, remainder) = U256::from_bytes(bytes)?;
        let (new_key, remainder) = Vec::from_bytes(remainder)?;
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

pub struct SetActionCount {
    pub action_count: u64,
    pub action_id: U256,
}

impl FromBytes for SetActionCount {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_count, remainder) = u64::from_bytes(bytes)?;
        let (action_id, remainder) = U256::from_bytes(remainder)?;
        Ok((
            Self {
                action_count,
                action_id,
            },
            remainder,
        ))
    }
}

impl ToBytes for SetActionCount {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.action_count.to_bytes()?);
        result.extend(self.action_id.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_count.serialized_length() + self.action_id.serialized_length()
    }
}

pub struct AddContractAddress {
    pub collection_address: ContractHash,
    pub contract_address: ContractHash,
}

impl FromBytes for AddContractAddress {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (collection_address, remainder) = ContractHash::from_bytes(bytes)?;
        let (contract_address, remainder) = ContractHash::from_bytes(remainder)?;
        Ok((
            Self {
                contract_address,
                collection_address,
            },
            remainder,
        ))
    }
}

impl ToBytes for AddContractAddress {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.collection_address.to_bytes()?);
        result.extend(self.contract_address.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.collection_address.serialized_length() + self.contract_address.serialized_length()
    }
}

#[derive(Clone)]
pub struct WithdrawFeeData {
    pub action_id: U256,
    pub receiver: AccountHash,
}

impl FromBytes for WithdrawFeeData {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (action_id, remainder) = U256::from_bytes(bytes)?;
        let (receiver, remainder) = AccountHash::from_bytes(remainder)?;
        Ok((
            Self {
                action_id,
                receiver,
            },
            remainder,
        ))
    }
}

impl ToBytes for WithdrawFeeData {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(self.action_id.to_bytes()?);
        result.extend(self.receiver.to_bytes()?);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.action_id.serialized_length() + self.action_id.serialized_length()
    }
}
