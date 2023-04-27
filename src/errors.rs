use casper_types::ApiError;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum BridgeError {
    AlreadyInitialized = 1,

    // Init Errors
    MissingArgumentGroupKey = 2,
    InvalidArgumentGroupKey = 3,
    MissingArgumentFeePublicKey = 4,
    InvalidArgumentFeePublicKey = 5,

    MissingConsumedActionsUref = 6,
    InvalidConsumedActionsUref = 7,
    MissingGroupKeyUref = 8,
    InvalidGroupKeyUref = 9,

    RetryingConsumedActions = 10,
    UnauthorizedAction = 11,

    ContractStatePaused = 12,
    FailedToTransferBwPursees = 13,

    IncorrectFeeSig = 14,
    MissingThisContractUref = 15,
    InvalidThisContractUref = 16,
    MissingFeePublicKeyUref = 17,
    InvalidFeePublicKeyUref = 18,

    UnexpectedKeyVariant = 67,
    FailedToCreateDictionary = 68,
    FailedToGetArgBytes = 69, // For Now
}

impl From<BridgeError> for ApiError {
    fn from(e: BridgeError) -> Self {
        ApiError::User(e as u16)
    }
}
