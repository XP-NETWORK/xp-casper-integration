#![no_std]
#![no_main]
#![allow(unused_imports)]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// This code imports necessary aspects of external crates that we will use in our contract code.
extern crate alloc;

mod entrypoints;
mod errors;
mod events;
mod keys;
mod structs;
mod utils;

// Importing Rust types.
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
// Importing aspects of the Casper platform.
use casper_contract::{
    contract_api::{runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
// Importing specific Casper types.
use casper_types::{
    api_error::ApiError,
    bytesrepr::serialize,
    contracts::{EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, NamedKeys},
    CLType, CLValue, URef, U256,
};

use ed25519_compact::{PublicKey, Signature};
use entrypoints::*;
use errors::BridgeError;
use keys::*;
use sha2::{Digest, Sha512};
use structs::{PauseData, UnpauseData};

pub const INITIALIZED: &str = "initialized";

pub const ARG_GROUP_KEY: &str = "group_key";
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

    storage::dictionary_put(consumed_actions_uref, &action_id.to_string(), true)
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

    storage::write(paused_uref, false)
}
