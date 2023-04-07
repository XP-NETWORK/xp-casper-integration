#![no_std]
#![no_main]
#![allow(unused_imports)]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// This code imports necessary aspects of external crates that we will use in our contract code.
extern crate alloc;

mod entrypoints;
mod errors;
mod keys;
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
    contracts::{EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, NamedKeys},
    CLType, CLValue, URef,
};
use entrypoints::*;
use errors::BridgeError;
use keys::*;

pub const INITIALIZED: &str = "initialized";

pub const ARG_GROUP_KEY: &str = "group_key";
pub const ARG_FEE_PUBLIC_KEY: &str = "fee_public_key";

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

    runtime::put_key(KEY_FEE_PUBLIC_KEY, storage::new_uref(fee_public_key).into());
    runtime::put_key(KEY_GROUP_KEY, storage::new_uref(group_key).into());
    storage::new_dictionary(KEY_WHITELIST_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);

    storage::new_dictionary(KEY_CONSUMED_ACTIONS_DICT)
        .unwrap_or_revert_with(BridgeError::FailedToCreateDictionary);
}
