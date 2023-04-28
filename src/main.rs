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
use alloc::{boxed::Box, format, string::ToString, vec, vec::Vec};
// Importing aspects of the Casper platform.
use casper_contract::{
    contract_api::{self, account, runtime, storage, system::transfer_to_account},
    unwrap_or_revert::UnwrapOrRevert,
};
// Importing specific Casper types.
use casper_types::{
    bytesrepr::serialize,
    contracts::{EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, NamedKeys},
    CLType, ContractHash, Key, Parameter, U256, U512,
};

use ed25519_compact::{PublicKey, Signature};
use entrypoints::*;
use errors::BridgeError;
use events::{TransferNftEvent, UnfreezeNftEvent};
use external::xp_nft::{burn, mint, transfer};
use keys::*;
use sha2::{Digest, Sha512};
use structs::{
    FreezeNFT, PauseData, TxFee, UnpauseData, UpdateGroupKey, ValidateTransferData,
    ValidateUnfreezeData, WithdrawNFT,
};

pub const INITIALIZED: &str = "initialized";
pub const THIS_CONTRACT: &str = "this_contract";
pub const INSTALLER: &str = "installer";

pub const ARG_GROUP_KEY: &str = "group_key";
pub const ARG_PAUSE_DATA: &str = "pause_data";
pub const ARG_UPDATE_GK: &str = "update_gk";
pub const ARG_FREEZE_DATA: &str = "freeze_data";
pub const ARG_WITHDRAW_DATA: &str = "withdraw_data";
pub const ARG_UNPAUSE_DATA: &str = "unpause_data";
pub const ARG_VALIDATE_TRANSFER_DATA: &str = "validate_transfer_data";
pub const ARG_SIG_DATA: &str = "sig_data";
pub const ARG_FEE_PUBLIC_KEY: &str = "fee_public_key";

fn check_consumed_action(action_id: &U256) -> bool {
    let consumed_actions_uref = utils::get_uref(
        KEY_CONSUMED_ACTIONS_DICT,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );

    storage::dictionary_get::<bool>(consumed_actions_uref, &action_id.to_string())
        .unwrap_or_revert()
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

    let group_key: [u8; 32] = storage::read(gk_uref).unwrap_or_revert().unwrap_or_revert();
    group_key
}

/// Ed25519 Signature verification logic.
/// Signature check for bridge actions.
/// Consumes the passed action_id.
fn require_sig(action_id: U256, data: Vec<u8>, sig_data: Vec<u8>, context: &[u8]) {
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

    let sig = Signature::new(sig_data.as_slice().try_into().unwrap());
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

    let group_key: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let fee_public_key: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_FEE_PUBLIC_KEY,
        BridgeError::MissingArgumentFeePublicKey,
        BridgeError::MissingArgumentFeePublicKey,
    )
    .unwrap_or_revert();

    runtime::put_key(INITIALIZED, storage::new_uref(true).into());

    runtime::put_key(KEY_PAUSED, storage::new_uref(false).into());

    runtime::put_key(KEY_PURSE, contract_api::system::create_purse().into());

    runtime::put_key(KEY_FEE_PUBLIC_KEY, storage::new_uref(fee_public_key).into());
    runtime::put_key(KEY_GROUP_KEY, storage::new_uref(group_key).into());
    storage::new_dictionary(KEY_WHITELIST_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);

    storage::new_dictionary(KEY_CONSUMED_ACTIONS_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);
}

#[no_mangle]
pub extern "C" fn validate_pause() {
    let data: PauseData = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data).unwrap_or_revert(),
        sig_data,
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
    let data: UnpauseData = utils::get_named_arg_with_user_errors(
        ARG_UNPAUSE_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data).unwrap_or_revert(),
        sig_data,
        b"SetPause",
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
    let data: UpdateGroupKey = utils::get_named_arg_with_user_errors(
        ARG_UNPAUSE_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert(),
        sig_data,
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
    let data: UpdateGroupKey = utils::get_named_arg_with_user_errors(
        ARG_UPDATE_GK,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert(),
        sig_data,
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
    let paused: bool = storage::read(paused_uref)
        .unwrap_or_revert()
        .unwrap_or_revert();

    if paused {
        runtime::revert(BridgeError::ContractStatePaused);
    }
}

pub fn require_tx_fees(amount: U512) {
    let contract_purse = utils::get_uref(
        KEY_PURSE,
        BridgeError::MissingConsumedActionsUref,
        BridgeError::InvalidConsumedActionsUref,
    );
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
    let data: ValidateTransferData = utils::get_named_arg_with_user_errors(
        ARG_VALIDATE_TRANSFER_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert(),
        sig_data,
        b"ValidateTransferNft",
    );

    mint(data.mint_with, data.receiver, data.metadata.clone());
}

#[no_mangle]
pub extern "C" fn validate_unfreeze_nft() {
    require_not_paused();
    let data: ValidateUnfreezeData = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert(),
        sig_data,
        b"ValidateUnfreezeNft",
    );

    let this_uref = utils::get_uref(
        THIS_CONTRACT,
        BridgeError::MissingThisContractUref,
        BridgeError::InvalidThisContractUref,
    );

    let this_contract: ContractHash = storage::read(this_uref)
        .unwrap_or_revert()
        .unwrap_or_revert();

    transfer(
        data.contract,
        this_contract.into(),
        data.receiver,
        data.token_id,
    );
}

#[no_mangle]
pub extern "C" fn freeze_nft() {
    require_not_paused();

    let data: FreezeNFT = utils::get_named_arg_with_user_errors(
        ARG_FREEZE_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_enough_fees(
        TxFee {
            from: 38,
            to: data.chain_nonce,
            receiver: data.to.clone(),
            value: data.amt,
        },
        data.sig_data,
    );

    transfer_tx_fees(data.amt.clone());

    let this_uref = utils::get_uref(
        THIS_CONTRACT,
        BridgeError::MissingThisContractUref,
        BridgeError::InvalidThisContractUref,
    );

    let this_contract: ContractHash = storage::read(this_uref)
        .unwrap_or_revert()
        .unwrap_or_revert();

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

    let data: WithdrawNFT = utils::get_named_arg_with_user_errors(
        ARG_FREEZE_DATA,
        BridgeError::MissingArgumentGroupKey,
        BridgeError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    require_enough_fees(
        TxFee {
            from: 38,
            to: data.chain_nonce,
            receiver: data.to.clone(),
            value: data.amt,
        },
        data.sig_data,
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

fn require_enough_fees(tx_fee: TxFee, sig_data: Vec<u8>) {
    let fee = serialize(tx_fee).unwrap();

    let gk_uref = utils::get_uref(
        KEY_FEE_PUBLIC_KEY,
        BridgeError::MissingArgumentFeePublicKey,
        BridgeError::InvalidArgumentFeePublicKey,
    );

    let group_key: [u8; 32] = storage::read(gk_uref).unwrap_or_revert().unwrap_or_revert();

    let mut hasher = Sha512::new();
    hasher.update(fee);
    let hash = hasher.finalize();

    let sig = Signature::new(sig_data.as_slice().try_into().unwrap());
    let key = PublicKey::new(group_key);
    let res = key.verify(hash, &sig);
    if !res.is_ok() {
        runtime::revert(BridgeError::IncorrectFeeSig);
    }
}

pub fn transfer_tx_fees(amount: U512) {
    let this_purse_uref = utils::get_uref(
        KEY_PURSE,
        BridgeError::MissingThisPurseUref,
        BridgeError::InvalidThisPurseUref,
    );

    let purse = storage::read(this_purse_uref)
        .unwrap_or_revert()
        .unwrap_or_revert();
    transfer_to_account(purse, amount, None).unwrap_or_revert();
}

fn generate_entry_points() -> EntryPoints {
    let mut entrypoints = EntryPoints::new();

    let init = EntryPoint::new(
        ENTRY_POINT_BRIDGE_INITIALIZE,
        vec![
            Parameter::new(ARG_GROUP_KEY, CLType::List(Box::new(CLType::U8))),
            Parameter::new(ARG_FEE_PUBLIC_KEY, CLType::List(Box::new(CLType::U8))),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let validate_pause = EntryPoint::new(
        ENTRY_POINT_BRIDGE_VALIDATE_PAUSE,
        vec![
            Parameter::new(ARG_PAUSE_DATA, CLType::List(Box::new(CLType::U8))),
            Parameter::new(ARG_SIG_DATA, CLType::List(Box::new(CLType::U8))),
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
            Parameter::new(
                ARG_VALIDATE_TRANSFER_DATA,
                CLType::List(Box::new(CLType::U8)),
            ),
            Parameter::new(ARG_SIG_DATA, CLType::List(Box::new(CLType::U8))),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    entrypoints.add_entry_point(init);
    entrypoints.add_entry_point(validate_pause);
    entrypoints.add_entry_point(validate_unpause);
    entrypoints.add_entry_point(validate_transfer_nft);
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

    let (contract_hash, _) = storage::new_locked_contract(
        entry_points,
        Some(named_keys),
        Some(hash_key_name.clone()),
        Some(format!("bridge")),
    );
    runtime::put_key(THIS_CONTRACT, storage::new_uref(contract_hash).into());
}

#[no_mangle]
pub extern "C" fn call() {
    install_contract();
}
