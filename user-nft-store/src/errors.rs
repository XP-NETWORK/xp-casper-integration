use casper_types::ApiError;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum UserNftStoreError {
    MissingArgumentContract = 500,
    InvalidArgumentContract,
    MissingArgumentTokenID,
    InvalidArgumentTokenID,
    MissingArgumentTo,
    InvalidArgumentTo,
    MissingArgumentMintWith,
    InvalidArgumentMintWith,
    MissingArgumentChainNonce,
    InvalidArgumentChainNonce,
    MissingArgumentAmount,
    InvalidArgumentAmount,
    MissingArgumentSigData,
    InvalidArgumentSigData,
    FailedToIncrementActionCount,
    FailedToSerializeTxFee,
    FailedToGetCallStack,
    FailedToParseContractHash,
    MissingReceiverAccountHash,
    InvalidReceiverAccountHash,
    MissingArgumentReceiver,
    InvalidArgumentReceiver,
    MissingArgumentActionID,
    InvalidArgumentActionID,
    FailedToSerializeActionStruct,
    MissingGroupKeyUref,
    InvalidGroupKeyUref,
    UnexpectedKeyVariant,
    FailedToGetArgBytes,
    MissingNoWhitelistContract,
    InvalidNoWhitelistContract,
    AlreadyInitialized
}

impl From<UserNftStoreError> for ApiError {
    fn from(e: UserNftStoreError) -> Self {
        ApiError::User(e as u16)
    }
}
