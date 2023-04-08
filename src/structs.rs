use alloc::vec::Vec;
use casper_types::{
    bytesrepr::{self, FromBytes, ToBytes},
    U256,
};

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
