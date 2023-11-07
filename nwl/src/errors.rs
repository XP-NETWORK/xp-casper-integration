use casper_types::ApiError;

/// An error enum which can be converted to a `u16` so it can be returned as an `ApiError::User`.
#[repr(u16)]
pub enum NwlError {
    MissingActionCount = 800,
    InvalidActionCount,
    FailedToConvertU64ToCLValue,
    MissingArgumentActionID,
    InvalidArgumentActionID,
    MissingArgumentGroupKey,
    InvalidArgumentGroupKey,
    FailedToSerializeActionStruct,
    MissingArgumentSigData,
    InvalidArgumentSigData,
    MissingGroupKeyUref,
    InvalidGroupKeyUref,
    RetryingConsumedActions,
    FailedToPrepareSignature,
    FailedToPreparePublicKey,
    UnauthorizedAction,
    MissingConsumedActionsUref,
    InvalidConsumedActionsUref,
    FailedToGetDictItem,
    FailedToGetArgBytes,
    UnexpectedKeyVariant,
    MissingFeePublicKeyUref,
    InvalidFeePublicKeyUref,
    MissingArgumentData,
    InvalidArgumentData,
    MissingArgumentFeePublicKey,
    InvalidArgumentFeePublicKey,
    MissingFeePublicKey,
    InvalidFeePublicKey,
    IncorrectFeeSig,
    MissingArgumentCollectionAddress,
    InvalidArgumentCollectionAddress,
    MissingArgumentContractAddress,
    InvalidArgumentContractAddress,
    MissingCollectionToContractUref,
    InvalidCollectionToContractUref,
    MissingContractToCollectionUref,
    InvalidContractToCollectionUref,
    MissingArgumentActionCount,
    InvalidArgumentActionCount,
    MissingArgumentReceiver,
    InvalidArgumentReceiver,
    MissingThisPurseUref,
    InvalidThisPurseUref,
    FailedToGetCallStack,
    FailedToParseContractHash,
    FailedToGetCollectionForContract,
    NoCollectionForContract,
}

impl From<NwlError> for ApiError {
    fn from(error: NwlError) -> Self {
        ApiError::User(error as u16)
    }
}