use casper_types::ApiError;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum BridgeError {
    AlreadyInitialized,

    // Init Errors
    MissingArgumentGroupKey,
    InvalidArgumentGroupKey,
    MissingArgumentFeePublicKey,
    InvalidArgumentFeePublicKey,
    MissingArgumentSigData,
    InvalidArgumentSigData,

    MissingArgumentActionID,
    InvalidArgumentActionID,

    MissingArgumentMintWith,
    InvalidArgumentMintWith,

    MissingArgumentReceiver,
    InvalidArgumentReceiver,

    MissingArgumentMetadata,
    InvalidArgumentMetadata,

    MissingArgumentTokenID,
    InvalidArgumentTokenID,

    MissingArgumentChainNonce,
    InvalidArgumentChainNonce,

    MissingArgumentAmount,
    InvalidArgumentAmount,

    MissingArgumentTo,
    InvalidArgumentTo,

    MissingArgumentContract,
    InvalidArgumentContract,

    MissingConsumedActionsUref,
    InvalidConsumedActionsUref,
    MissingGroupKeyUref,
    InvalidGroupKeyUref,

    RetryingConsumedActions,
    UnauthorizedAction,

    ContractStatePaused,
    FailedToTransferBwPursees,

    IncorrectFeeSig,
    MissingThisContractUref,
    InvalidThisContractUref,
    MissingFeePublicKeyUref,
    InvalidFeePublicKeyUref,
    MissingThisPurseUref,
    InvalidThisPurseUref,
    NotWhitelistedContract,
    UnexpectedKeyVariant,
    FailedToCreateDictionary,
    FailedToGetArgBytes,
}

impl From<BridgeError> for ApiError {
    fn from(e: BridgeError) -> Self {
        ApiError::User(e as u16)
    }
}
