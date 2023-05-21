#![no_std]
#![no_main]

// #[cfg(not(target_arch = "wasm32"))]
// compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// This code imports necessary aspects of external crates that we will use in our contract code.
extern crate alloc;

mod entrypoints;
mod errors;
mod events;
mod external;
mod keys;
mod structs;
mod utils;

// Importing Rust types.
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
// Importing aspects of the Casper platform.
use casper_contract::{
    contract_api::{
        self, account,
        runtime::{self},
        storage,
        system::{transfer_from_purse_to_account, transfer_from_purse_to_purse},
    },
    unwrap_or_revert::UnwrapOrRevert,
};
// Importing specific Casper types.
use casper_types::{
    account::AccountHash,
    bytesrepr::{serialize, Bytes, ToBytes},
    contracts::{EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, NamedKeys},
    system::{auction::ARG_AMOUNT, mint::ARG_TO},
    CLType, ContractHash, Key, Parameter, URef, U256, U512,
};

use ed25519_compact::{PublicKey, Signature};
use entrypoints::*;
use errors::BridgeError;
use events::{TransferNftEvent, UnfreezeNftEvent};
use external::xp_nft::{burn, mint, transfer, TokenIdentifier};
use keys::*;
use sha2::{Digest, Sha512};
use structs::{
    FreezeNFT, PauseData, TxFee, UnpauseData, UpdateGroupKey, ValidateBlacklist,
    ValidateTransferData, ValidateUnfreezeData, ValidateWhitelist, WithdrawFeeData, WithdrawNFT,
};

pub const INITIALIZED: &str = "initialized";
pub const THIS_CONTRACT: &str = "this_contract";
pub const INSTALLER: &str = "installer";

pub const ARG_GROUP_KEY: &str = "group_key";
pub const ARG_ACTION_ID: &str = "action_id";
pub const ARG_PAUSE_DATA: &str = "pause_data";
pub const ARG_UPDATE_GK: &str = "update_gk";
pub const ARG_FREEZE_DATA: &str = "freeze_data";
pub const ARG_WITHDRAW_DATA: &str = "withdraw_data";
pub const ARG_WHITELIST_DATA: &str = "whitelist_data";
pub const ARG_BLACKLIST_DATA: &str = "blacklist_data";
pub const ARG_UNPAUSE_DATA: &str = "unpause_data";
pub const ARG_MINT_WITH: &str = "mint_with";
pub const ARG_CONTRACT: &str = "contract";
pub const ARG_VALIDATE_UNFREEZE_DATA: &str = "validate_unfreeze_data";
pub const ARG_SIG_DATA: &str = "sig_data";
pub const ARG_RECEIVER: &str = "receiver";
pub const ARG_METADATA: &str = "metadata";
pub const ARG_CHAIN_NONCE: &str = "chain_nonce";
pub const ARG_TOKEN_ID: &str = "token_id";
pub const KEY_PURSE: &str = "bridge_purse";
pub const ARG_FEE_PUBLIC_KEY: &str = "fee_public_key";
pub const ARG_WHITELIST: &str = "whitelist";

fn check_consumed_action(action_id: &U256) -> bool {
    let consumed_actions_uref = utils::get_uref(
        KEY_CONSUMED_ACTIONS_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    storage::dictionary_get::<bool>(consumed_actions_uref, &action_id.to_string())
        .unwrap_or_revert_with(BridgeError::FailedToGetDictItem)
        .is_none()
}

fn insert_consumed_action(action_id: &U256) {
    let consumed_actions_uref = utils::get_uref(
        KEY_CONSUMED_ACTIONS_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    storage::dictionary_put::<bool>(consumed_actions_uref, &action_id.to_string(), true)
}

pub fn get_group_key() -> [u8; 32] {
    let gk_uref = utils::get_uref(
        KEY_GROUP_KEY,
        BridgeError::MissingGroupKeyUref,
        BridgeError::InvalidGroupKeyUref,
    );

    let group_key: [u8; 32] = storage::read_or_revert(gk_uref);
    group_key
}

/// Ed25519 Signature verification logic.
/// Signature check for bridge actions.
/// Consumes the passed action_id.
fn require_sig(action_id: U256, data: Vec<u8>, sig_data: &[u8], context: &[u8]) {
    let f = check_consumed_action(&action_id);

    if !f {
        runtime::revert(BridgeError::RetryingConsumedActions);
    }

    insert_consumed_action(&action_id);

    let mut hasher = Sha512::new();
    hasher.update(context);
    hasher.update(data);
    let hash = hasher.finalize();

    let group_key = get_group_key();

    let sig = Signature::new(
        sig_data
            .try_into()
            .map_err(|_| BridgeError::FailedToPrepareSignature)
            .unwrap_or_revert_with(BridgeError::FailedToPrepareSignature),
    );
    let key = PublicKey::new(group_key);
    let res = key.verify(hash, &sig);
    if !res.is_ok() {
        runtime::revert(BridgeError::UnauthorizedAction);
    }
}

#[no_mangle]
pub extern "C" fn init() {
    if utils::named_uref_exists(INITIALIZED) {
        runtime::revert(BridgeError::AlreadyInitialized);
    }

    let group_key: [u8; 32] = runtime::get_named_arg(ARG_GROUP_KEY);

    let fee_public_key: [u8; 32] = runtime::get_named_arg(ARG_FEE_PUBLIC_KEY);

    let whitelist_contracts: Vec<ContractHash> = runtime::get_named_arg(ARG_WHITELIST);

    runtime::put_key(INITIALIZED, storage::new_uref(true).into());

    runtime::put_key(KEY_PAUSED, storage::new_uref(false).into());

    runtime::put_key(KEY_PURSE, contract_api::system::create_purse().into());

    runtime::put_key(KEY_FEE_PUBLIC_KEY, storage::new_uref(fee_public_key).into());
    runtime::put_key(KEY_GROUP_KEY, storage::new_uref(group_key).into());
    let whitelist = storage::new_dictionary(KEY_WHITELIST_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);

    storage::new_dictionary(KEY_CONSUMED_ACTIONS_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);
    whitelist_contracts
        .iter()
        .for_each(|c| storage::dictionary_put(whitelist, &c.to_string(), true));
}

#[no_mangle]
pub extern "C" fn validate_pause() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let data = PauseData { action_id };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        data.to_bytes()
            .unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"SetPause",
    );

    let paused_uref = utils::get_uref(
        KEY_PAUSED,
        BridgeError::MissingGroupKeyUref,
        BridgeError::InvalidGroupKeyUref,
    );

    storage::write(paused_uref, true)
}

#[no_mangle]
pub extern "C" fn validate_unpause() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let data = UnpauseData { action_id };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"SetUnpause",
    );

    let paused_uref = utils::get_uref(
        KEY_PAUSED,
        BridgeError::MissingGroupKeyUref,
        BridgeError::InvalidGroupKeyUref,
    );

    storage::write(paused_uref, false)
}

#[no_mangle]
pub extern "C" fn validate_update_group_key() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let new_key: [u8; 32] = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let data = UpdateGroupKey {
        action_id,
        new_key: new_key.to_vec(),
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"UpdateGroupKey",
    );

    let gk_uref = utils::get_uref(
        KEY_GROUP_KEY,
        BridgeError::MissingGroupKeyUref,
        BridgeError::InvalidGroupKeyUref,
    );

    storage::write(gk_uref, data.new_key.clone())
}

#[no_mangle]
pub extern "C" fn validate_update_fee_pk() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let new_key: [u8; 32] = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let data = UpdateGroupKey {
        action_id,
        new_key: new_key.to_vec(),
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"UpdateFeePk",
    );

    let fee_pk_uref = utils::get_uref(
        KEY_FEE_PUBLIC_KEY,
        BridgeError::MissingFeePublicKeyUref,
        BridgeError::InvalidFeePublicKeyUref,
    );

    storage::write(fee_pk_uref, data.new_key.clone())
}

pub fn require_not_paused() {
    let paused_uref = utils::get_uref(
        KEY_PAUSED,
        BridgeError::MissingGroupKeyUref,
        BridgeError::InvalidGroupKeyUref,
    );
    let paused: bool = storage::read_or_revert(paused_uref);

    if paused {
        runtime::revert(BridgeError::ContractStatePaused);
    }
}

pub fn require_tx_fees(amount: U512) {
    let contract_purse = contract_api::account::get_main_purse();
    casper_contract::contract_api::system::transfer_from_purse_to_purse(
        account::get_main_purse(),
        contract_purse,
        amount,
        None,
    )
    .unwrap_or_revert_with(BridgeError::FailedToTransferBwPursees)
}

#[no_mangle]
pub extern "C" fn validate_transfer_nft() {
    require_not_paused();

    let mint_with: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_MINT_WITH,
        BridgeError::MissingArgumentMintWith,
        BridgeError::InvalidArgumentMintWith,
    )
    .unwrap_or_revert();

    let receiver: Key = utils::get_named_arg_with_user_errors(
        ARG_RECEIVER,
        BridgeError::MissingArgumentReceiver,
        BridgeError::InvalidArgumentReceiver,
    )
    .unwrap_or_revert();

    let metadata: String = utils::get_named_arg_with_user_errors(
        ARG_METADATA,
        BridgeError::MissingArgumentMetadata,
        BridgeError::InvalidArgumentMetadata,
    )
    .unwrap_or_revert();
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let data = ValidateTransferData {
        action_id,
        mint_with,
        metadata,
        receiver,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"ValidateTransferNft",
    );

    mint(data.mint_with, data.receiver, data.metadata.clone());
}

#[no_mangle]
pub extern "C" fn validate_unfreeze_nft() {
    require_not_paused();

    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        BridgeError::MissingArgumentContract,
        BridgeError::InvalidArgumentContract,
    )
    .unwrap_or_revert();

    let receiver: Key = utils::get_named_arg_with_user_errors(
        ARG_RECEIVER,
        BridgeError::MissingArgumentReceiver,
        BridgeError::InvalidArgumentReceiver,
    )
    .unwrap_or_revert();

    let token_id: TokenIdentifier = utils::get_named_arg_with_user_errors(
        ARG_TOKEN_ID,
        BridgeError::MissingArgumentTokenID,
        BridgeError::InvalidArgumentTokenID,
    )
    .unwrap_or_revert();
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let data = ValidateUnfreezeData {
        action_id,
        contract,
        token_id,
        receiver,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"ValidateUnfreezeNft",
    );

    require_whitelist(data.contract);

    let this_uref = utils::get_uref(
        THIS_CONTRACT,
        BridgeError::MissingThisContractUref,
        BridgeError::InvalidThisContractUref,
    );

    let this_contract: ContractHash = storage::read_or_revert(this_uref);
    transfer(
        data.contract,
        this_contract.into(),
        data.receiver,
        data.token_id,
    );
}

#[no_mangle]
pub extern "C" fn validate_withdraw_fees() {
    require_not_paused();
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let receiver: AccountHash = utils::get_named_arg_with_user_errors(
        ARG_RECEIVER,
        BridgeError::MissingArgumentReceiver,
        BridgeError::InvalidArgumentReceiver,
    )
    .unwrap_or_revert();

    let data = WithdrawFeeData {
        action_id,
        receiver,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"ValidateWithdrawFees",
    );

    let this_contract_purse_uref = utils::get_uref(
        KEY_PURSE,
        BridgeError::MissingThisPurseUref,
        BridgeError::InvalidThisPurseUref,
    );

    let purse: URef = storage::read_or_revert(this_contract_purse_uref);

    let bal = contract_api::system::get_purse_balance(purse).unwrap_or(U512::from(0));
    transfer_from_purse_to_account(purse, data.receiver, bal, None).unwrap_or_revert();
}

fn require_whitelist(contract: ContractHash) {
    let whitelist_uref = utils::get_uref(
        KEY_WHITELIST_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    let value = storage::dictionary_get::<bool>(whitelist_uref, &contract.to_string())
        .unwrap_or_revert()
        .unwrap_or(false);

    if !value {
        runtime::revert(BridgeError::NotWhitelistedContract)
    }
}
#[no_mangle]
pub extern "C" fn validate_whitelist() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        BridgeError::MissingArgumentContract,
        BridgeError::InvalidArgumentContract,
    )
    .unwrap_or_revert();
    let data = ValidateWhitelist {
        action_id,
        contract,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"WhitelistNftAction",
    );

    let whitelist_uref = utils::get_uref(
        KEY_WHITELIST_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    storage::dictionary_put(whitelist_uref, &data.contract.to_string(), true)
}

#[no_mangle]
pub extern "C" fn validate_blacklist() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        BridgeError::MissingArgumentActionID,
        BridgeError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        BridgeError::MissingArgumentContract,
        BridgeError::InvalidArgumentContract,
    )
    .unwrap_or_revert();
    let data = ValidateBlacklist {
        action_id,
        contract,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(BridgeError::FailedToSerializeActionStruct),
        &sig_data,
        b"BlacklistNftAction",
    );

    let whitelist_uref = utils::get_uref(
        KEY_WHITELIST_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    storage::dictionary_put(whitelist_uref, &data.contract.to_string(), false)
}

#[no_mangle]
pub extern "C" fn freeze_nft() {
    require_not_paused();

    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        BridgeError::MissingArgumentContract,
        BridgeError::InvalidArgumentContract,
    )
    .unwrap_or_revert();
    let token_id: TokenIdentifier = utils::get_named_arg_with_user_errors(
        ARG_TOKEN_ID,
        BridgeError::MissingArgumentTokenID,
        BridgeError::InvalidArgumentTokenID,
    )
    .unwrap_or_revert();
    let to: String = utils::get_named_arg_with_user_errors(
        ARG_TO,
        BridgeError::MissingArgumentTo,
        BridgeError::InvalidArgumentTo,
    )
    .unwrap_or_revert();
    let mint_with: String = utils::get_named_arg_with_user_errors(
        ARG_MINT_WITH,
        BridgeError::MissingArgumentMintWith,
        BridgeError::InvalidArgumentMintWith,
    )
    .unwrap_or_revert();

    let chain_nonce: u8 = utils::get_named_arg_with_user_errors(
        ARG_CHAIN_NONCE,
        BridgeError::MissingArgumentChainNonce,
        BridgeError::InvalidArgumentChainNonce,
    )
    .unwrap_or_revert();
    let amt: U512 = utils::get_named_arg_with_user_errors(
        ARG_AMOUNT,
        BridgeError::MissingArgumentAmount,
        BridgeError::InvalidArgumentAmount,
    )
    .unwrap_or_revert();
    let sig_data: Bytes = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let data = FreezeNFT {
        amt,
        chain_nonce,
        contract,
        mint_with,
        sig_data,
        token_id,
        to,
    };

    require_enough_fees(
        TxFee {
            from: 38,
            to: data.chain_nonce,
            receiver: data.to.clone(),
            value: data.amt,
        },
        &data.sig_data,
    );

    require_whitelist(data.contract);

    transfer_tx_fees(data.amt.clone());

    let this_uref = utils::get_uref(
        THIS_CONTRACT,
        BridgeError::MissingThisContractUref,
        BridgeError::InvalidThisContractUref,
    );

    let this_contract: ContractHash = storage::read_or_revert(this_uref);

    transfer(
        data.contract,
        Key::Account(runtime::get_caller()),
        this_contract.into(),
        data.token_id.clone(),
    );
    let ev = TransferNftEvent {
        amt: data.amt,
        chain_nonce: data.chain_nonce,
        to: data.to,
        contract: data.contract.to_string(),
        token_id: data.token_id,
        mint_with: data.mint_with,
    };
    casper_event_standard::emit(ev);
}

#[no_mangle]
pub extern "C" fn withdraw_nft() {
    require_not_paused();

    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        BridgeError::MissingArgumentContract,
        BridgeError::InvalidArgumentContract,
    )
    .unwrap_or_revert();
    let token_id: TokenIdentifier = utils::get_named_arg_with_user_errors(
        ARG_TOKEN_ID,
        BridgeError::MissingArgumentTokenID,
        BridgeError::InvalidArgumentTokenID,
    )
    .unwrap_or_revert();
    let to: String = utils::get_named_arg_with_user_errors(
        ARG_TO,
        BridgeError::MissingArgumentTo,
        BridgeError::InvalidArgumentTo,
    )
    .unwrap_or_revert();

    let chain_nonce: u8 = utils::get_named_arg_with_user_errors(
        ARG_CHAIN_NONCE,
        BridgeError::MissingArgumentChainNonce,
        BridgeError::InvalidArgumentChainNonce,
    )
    .unwrap_or_revert();
    let amt: U512 = utils::get_named_arg_with_user_errors(
        ARG_AMOUNT,
        BridgeError::MissingArgumentAmount,
        BridgeError::InvalidArgumentAmount,
    )
    .unwrap_or_revert();
    let sig_data: Bytes = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentSigData,
        BridgeError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let data = WithdrawNFT {
        amt,
        chain_nonce,
        contract,
        token_id,
        sig_data,
        to,
    };

    require_enough_fees(
        TxFee {
            from: 38,
            to: data.chain_nonce,
            receiver: data.to.clone(),
            value: data.amt,
        },
        &data.sig_data,
    );

    transfer_tx_fees(data.amt.clone());

    burn(data.contract, data.token_id.clone());
    let ev = UnfreezeNftEvent {
        amt: data.amt,
        chain_nonce: data.chain_nonce,
        to: data.to,
        contract: data.contract.to_string(),
        token_id: data.token_id,
    };
    casper_event_standard::emit(ev);
}

fn require_enough_fees(tx_fee: TxFee, sig_data: &[u8]) {
    let fee = serialize(tx_fee).unwrap_or_revert_with(BridgeError::FailedToSerializeTxFee);

    let gk_uref = utils::get_uref(
        KEY_FEE_PUBLIC_KEY,
        BridgeError::MissingArgumentFeePublicKey,
        BridgeError::InvalidArgumentFeePublicKey,
    );

    let group_key: [u8; 32] = storage::read_or_revert(gk_uref);

    let mut hasher = Sha512::new();
    hasher.update(fee);
    let hash = hasher.finalize();

    let sig = Signature::new(
        sig_data
            .try_into()
            .map_err(|_| BridgeError::FailedToPrepareSignature)
            .unwrap_or_revert_with(BridgeError::FailedToPrepareSignature),
    );
    let key = PublicKey::new(group_key);
    let res = key.verify(hash, &sig);
    if !res.is_ok() {
        runtime::revert(BridgeError::IncorrectFeeSig);
    }
}

pub fn transfer_tx_fees(amount: U512) {
    let this_uref = utils::get_uref(
        KEY_PURSE,
        BridgeError::MissingThisContractUref,
        BridgeError::InvalidThisContractUref,
    );

    let this_contract: URef = storage::read_or_revert(this_uref);

    transfer_from_purse_to_purse(account::get_main_purse(), this_contract, amount, None)
        .unwrap_or_revert();
}

fn generate_entry_points() -> EntryPoints {
    let mut entrypoints = EntryPoints::new();

    let init = EntryPoint::new(
        ENTRY_POINT_BRIDGE_INITIALIZE,
        vec![
            Parameter::new(ARG_GROUP_KEY, CLType::ByteArray(32)),
            Parameter::new(ARG_FEE_PUBLIC_KEY, CLType::ByteArray(32)),
            Parameter::new(ARG_WHITELIST, CLType::List(Box::new(CLType::ByteArray(32)))),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let validate_pause = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_PAUSE,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_unpause = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_UNPAUSE,
        vec![Parameter::new(
            ARG_UNPAUSE_DATA,
            CLType::List(Box::new(CLType::U8)),
        )],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let validate_transfer_nft = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_TRANSFER_NFT,
        vec![
            Parameter::new(ARG_MINT_WITH, CLType::ByteArray(32)),
            Parameter::new(ARG_RECEIVER, CLType::Key),
            Parameter::new(ARG_METADATA, CLType::String),
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_unfreeze_nft = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_UNFREEZE_NFT,
        vec![
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_RECEIVER, CLType::Key),
            Parameter::new(ARG_TOKEN_ID, CLType::String),
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let freeze_nft = EntryPoint::new(
        ENTRY_POINT_BRIDGE_FREEZE,
        vec![
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_TOKEN_ID, CLType::String),
            Parameter::new(ARG_TO, CLType::String),
            Parameter::new(ARG_MINT_WITH, CLType::String),
            Parameter::new(ARG_CHAIN_NONCE, CLType::U8),
            Parameter::new(ARG_AMOUNT, CLType::U512),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let withdraw_nft = EntryPoint::new(
        ENTRY_POINT_BRIDGE_WITHDRAW,
        vec![
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_TOKEN_ID, CLType::String),
            Parameter::new(ARG_TO, CLType::String),
            Parameter::new(ARG_CHAIN_NONCE, CLType::U8),
            Parameter::new(ARG_AMOUNT, CLType::U512),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_update_group_key = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_UPDATE_GK,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_GROUP_KEY, CLType::ByteArray(32)),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let validate_update_fee_pk = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_UPDATE_FEE_PK,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_GROUP_KEY, CLType::ByteArray(32)),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_withdraw_fees = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_WITHDRAW_FEES,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_RECEIVER, CLType::Key),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_whitelist = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_WHITELIST,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let validate_blacklist = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_BLACKLIST,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    entrypoints.add_entry_point(init); // Not needed
    entrypoints.add_entry_point(validate_pause); // Done
    entrypoints.add_entry_point(validate_unpause); // Done
    entrypoints.add_entry_point(validate_transfer_nft); // Done
    entrypoints.add_entry_point(validate_unfreeze_nft); // Done
    entrypoints.add_entry_point(validate_update_group_key); // Done
    entrypoints.add_entry_point(validate_update_fee_pk); // Done
    entrypoints.add_entry_point(validate_withdraw_fees); // Done
    entrypoints.add_entry_point(validate_whitelist); // Done
    entrypoints.add_entry_point(validate_blacklist); // Done
    entrypoints.add_entry_point(freeze_nft); // Done
    entrypoints.add_entry_point(withdraw_nft);
    entrypoints
}

fn install_contract() {
    let entry_points = generate_entry_points();
    let named_keys = {
        let mut named_keys = NamedKeys::new();
        named_keys.insert(INSTALLER.to_string(), runtime::get_caller().into());

        named_keys
    };

    let hash_key_name = format!("bridge");

    let (contract_hash, _) = storage::new_contract(
        entry_points,
        Some(named_keys),
        Some(hash_key_name.clone()),
        Some(format!("bridge")),
    );

    let num: U512 = runtime::get_named_arg("number");

    runtime::put_key(
        &(THIS_CONTRACT.to_string() + &num.to_string()),
        contract_hash.into(),
    );
}

#[no_mangle]
pub extern "C" fn call() {
    install_contract();
}
