#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

use core::convert::TryInto;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use alloc::{format, string::ToString};

use casper_contract::contract_api::runtime::call_contract;
use casper_contract::{
    contract_api::{self, runtime, storage, system::transfer_from_purse_to_account},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::runtime_args;
use casper_types::{
    account::AccountHash, bytesrepr::serialize, contracts::NamedKeys, CLType, CLValue,
    ContractHash, EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, Parameter,
    RuntimeArgs, URef, U256, U512,
};

use constants::*;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use errors::NwlError;
use sha2::{Digest, Sha512};
use structs::{AddContractAddress, SetActionCount, UpdateGroupKey, WithdrawFeeData};

mod constants;
mod errors;
mod structs;
mod utils;

fn require_only_allowed(contract_hash: ContractHash) {
    let dict_uref = utils::get_uref(
        CONTRACT_TO_COLLECTION_DICT,
        NwlError::MissingContractToCollectionUref,
        NwlError::InvalidContractToCollectionUref,
    );

    storage::dictionary_get::<ContractHash>(dict_uref, &contract_hash.to_string())
        .unwrap_or_revert_with(NwlError::FailedToGetCollectionForContract)
        .unwrap_or_revert_with(NwlError::NoCollectionForContract);
}

pub fn get_caller_hash() -> ContractHash {
    contract_api::runtime::get_call_stack()
        .iter()
        .nth_back(1)
        .unwrap_or_revert_with(NwlError::FailedToGetCallStack)
        .contract_hash()
        .unwrap_or_revert_with(NwlError::FailedToParseContractHash)
        .clone()
}

#[no_mangle]
pub extern "C" fn increment_action_count() {
    require_only_allowed(get_caller_hash());
    let uref = utils::get_uref(
        ACTION_COUNT,
        NwlError::MissingActionCount,
        NwlError::InvalidActionCount,
    );

    let action_count: u64 = storage::read_or_revert(uref);

    let new_action_count = action_count + 1;
    storage::write(uref, new_action_count);
    runtime::ret(CLValue::from_t(true).unwrap())
}

#[no_mangle]
pub extern "C" fn get_action_count() {
    let uref = utils::get_uref(
        ACTION_COUNT,
        NwlError::MissingActionCount,
        NwlError::InvalidActionCount,
    );

    let action_count: u64 = storage::read_or_revert(uref);
    runtime::ret(
        CLValue::from_t(action_count).unwrap_or_revert_with(NwlError::FailedToConvertU64ToCLValue),
    )
}

pub extern "C" fn set_action_count() {
    let action_count: u64 = utils::get_named_arg_with_user_errors(
        ACTION_COUNT,
        NwlError::MissingArgumentActionCount,
        NwlError::InvalidArgumentActionCount,
    )
    .unwrap_or_revert();

    let action_id = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let data = SetActionCount {
        action_count,
        action_id,
    };

    require_sig(
        action_id,
        serialize(data).unwrap_or_revert_with(NwlError::FailedToSerializeActionStruct),
        &sig_data,
        b"SetActionCntAction",
    );

    let uref = utils::get_uref(
        ACTION_COUNT,
        NwlError::MissingActionCount,
        NwlError::InvalidActionCount,
    );

    storage::write(uref, action_count);
}

#[no_mangle]
pub extern "C" fn validate_update_group_key() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let new_key: [u8; 32] = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        NwlError::MissingArgumentGroupKey,
        NwlError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let data = UpdateGroupKey {
        action_id,
        new_key: new_key.to_vec(),
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(NwlError::FailedToSerializeActionStruct),
        &sig_data,
        b"UpdateGroupKey",
    );

    let gk_uref = utils::get_uref(
        KEY_GROUP_KEY,
        NwlError::MissingGroupKeyUref,
        NwlError::InvalidGroupKeyUref,
    );

    storage::write(gk_uref, data.new_key)
}

/// Ed25519 Signature verification logic.
/// Signature check for bridge actions.
/// Consumes the passed action_id.
fn require_sig(action_id: U256, data: Vec<u8>, sig_data: &[u8], context: &[u8]) {
    let f = check_consumed_action(&action_id);

    if !f {
        runtime::revert(NwlError::RetryingConsumedActions);
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
            .map_err(|_| NwlError::FailedToPrepareSignature)
            .unwrap_or_revert(),
    );
    let key = PublicKey::from_bytes(group_key.as_slice())
        .map_err(|_| NwlError::FailedToPreparePublicKey)
        .unwrap_or_revert();
    let res = key.verify(&hash, &sig);
    if res.is_err() {
        runtime::revert(NwlError::UnauthorizedAction);
    }
}

pub fn get_group_key() -> [u8; 32] {
    let gk_uref = utils::get_uref(
        KEY_GROUP_KEY,
        NwlError::MissingGroupKeyUref,
        NwlError::InvalidGroupKeyUref,
    );

    let group_key: [u8; 32] = storage::read_or_revert(gk_uref);
    group_key
}

fn check_consumed_action(action_id: &U256) -> bool {
    let consumed_actions_uref = utils::get_uref(
        KEY_CONSUMED_ACTIONS_DICT,
        NwlError::MissingConsumedActionsUref,
        NwlError::InvalidConsumedActionsUref,
    );

    storage::dictionary_get::<bool>(consumed_actions_uref, &action_id.to_string())
        .unwrap_or_revert_with(NwlError::FailedToGetDictItem)
        .is_none()
}

fn insert_consumed_action(action_id: &U256) {
    let consumed_actions_uref = utils::get_uref(
        KEY_CONSUMED_ACTIONS_DICT,
        NwlError::MissingConsumedActionsUref,
        NwlError::InvalidConsumedActionsUref,
    );

    storage::dictionary_put::<bool>(consumed_actions_uref, &action_id.to_string(), true)
}

#[no_mangle]
pub extern "C" fn require_sig_verification() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        "action_id",
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let data: Vec<u8> = utils::get_named_arg_with_user_errors(
        "data",
        NwlError::MissingArgumentData,
        NwlError::InvalidArgumentData,
    )
    .unwrap_or_revert();
    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        "sig_data",
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();
    let context: Vec<u8> = utils::get_named_arg_with_user_errors(
        "context",
        NwlError::MissingArgumentContext,
        NwlError::InvalidArgumentContext,
    )
    .unwrap_or_revert();

    require_sig(action_id, data, &sig_data, &context);
}

#[no_mangle]
pub extern "C" fn validate_withdraw_fees() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();
    let receiver: AccountHash = utils::get_named_arg_with_user_errors(
        ARG_RECEIVER,
        NwlError::MissingArgumentReceiver,
        NwlError::InvalidArgumentReceiver,
    )
    .unwrap_or_revert();

    let data = WithdrawFeeData {
        action_id,
        receiver,
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(NwlError::FailedToSerializeActionStruct),
        &sig_data,
        b"ValidateWithdrawFees",
    );

    let this_contract_purse_uref = utils::get_uref(
        KEY_PURSE,
        NwlError::MissingThisPurseUref,
        NwlError::InvalidThisPurseUref,
    );

    let purse: URef = storage::read_or_revert(this_contract_purse_uref);

    let bal = contract_api::system::get_purse_balance(purse).unwrap_or(U512::from(0));
    transfer_from_purse_to_account(purse, data.receiver, bal, None).unwrap_or_revert();
}

#[no_mangle]
pub extern "C" fn require_enough_fees() {
    let fee: Vec<u8> = utils::get_named_arg_with_user_errors(
        "data",
        NwlError::MissingArgumentDataInFee,
        NwlError::InvalidArgumentDataInFee,
    )
    .unwrap_or_revert();
    let sig_data: Vec<u8> = utils::get_named_arg_with_user_errors(
        "sig_data",
        NwlError::MissingArgumentSigDataInFee,
        NwlError::InvalidArgumentSigDataInFee,
    )
    .unwrap_or_revert();

    let fk_uref = utils::get_uref(
        KEY_FEE_PUBLIC_KEY,
        NwlError::MissingArgumentFeePublicKey,
        NwlError::InvalidArgumentFeePublicKey,
    );

    let fee_key: [u8; 32] = storage::read(fk_uref)
        .unwrap_or_revert_with(NwlError::MissingFeePublicKey)
        .unwrap_or_revert_with(NwlError::InvalidFeePublicKey);

    let mut hasher = Sha512::new();
    hasher.update(fee);
    let hash = hasher.finalize();

    let sig = Signature::new(
        sig_data
            .try_into()
            .map_err(|_| NwlError::FailedToPrepareSignature)
            .unwrap_or_revert(),
    );
    let key = PublicKey::from_bytes(fee_key.as_slice())
        .map_err(|_| NwlError::FailedToPreparePublicKey)
        .unwrap_or_revert();
    let res = key.verify(&hash, &sig);
    if res.is_err() {
        runtime::revert(NwlError::IncorrectFeeSig);
    }
}

#[no_mangle]
pub extern "C" fn add_new_contract_address() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let collection_address: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_COLLECTION_ADDRESS,
        NwlError::MissingArgumentCollectionAddress,
        NwlError::InvalidArgumentCollectionAddress,
    )
    .unwrap_or_revert();

    let contract_address: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT_ADDRESS,
        NwlError::MissingArgumentContractAddress,
        NwlError::InvalidArgumentContractAddress,
    )
    .unwrap_or_revert();

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let action = AddContractAddress {
        collection_address,
        contract_address: runtime::get_call_stack()
            .last()
            .unwrap_or_revert_with(NwlError::FailedToGetLastContractHash)
            .contract_hash()
            .unwrap_or_revert_with(NwlError::FailedToConvertToContractHash)
            .clone(),
    };

    require_sig(
        action_id,
        serialize(action).unwrap_or_revert_with(NwlError::FailedToSerializeActionStruct),
        &sig_data,
        b"AddContractAddress",
    );

    let collection_to_contract = utils::get_uref(
        COLLECTION_TO_CONTRACT_DICT,
        NwlError::MissingCollectionToContractUref,
        NwlError::InvalidCollectionToContractUref,
    );
    let contract_to_collection = utils::get_uref(
        CONTRACT_TO_COLLECTION_DICT,
        NwlError::MissingContractToCollectionUref,
        NwlError::InvalidContractToCollectionUref,
    );

    storage::dictionary_put(
        collection_to_contract,
        &collection_address.to_string(),
        contract_address,
    );

    storage::dictionary_put(
        contract_to_collection,
        &contract_address.to_string(),
        collection_address,
    );
}

#[no_mangle]
pub extern "C" fn validate_update_fee_pk() {
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        NwlError::MissingArgumentActionID,
        NwlError::InvalidArgumentActionID,
    )
    .unwrap_or_revert();

    let new_key: [u8; 32] = utils::get_named_arg_with_user_errors(
        ARG_GROUP_KEY,
        NwlError::MissingArgumentGroupKey,
        NwlError::InvalidArgumentGroupKey,
    )
    .unwrap_or_revert();

    let data = UpdateGroupKey {
        action_id,
        new_key: new_key.to_vec(),
    };

    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        NwlError::MissingArgumentSigData,
        NwlError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    require_sig(
        data.action_id,
        serialize(data.clone()).unwrap_or_revert_with(NwlError::FailedToSerializeActionStruct),
        &sig_data,
        b"UpdateFeePk",
    );

    let fee_pk_uref = utils::get_uref(
        KEY_FEE_PUBLIC_KEY,
        NwlError::MissingFeePublicKeyUref,
        NwlError::InvalidFeePublicKeyUref,
    );

    storage::write(fee_pk_uref, data.new_key)
}

pub fn generate_entry_points() -> EntryPoints {
    
    let init = EntryPoint::new(
        ENTRY_POINT_INIT_CONTRACT,
        vec![],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let add_contract_address = EntryPoint::new(
        ENTRY_POINT_BRIDGE_ADD_NEW_CONTRACT_ADDRESS,
        vec![
            Parameter::new(ARG_ACTION_ID, CLType::U256),
            Parameter::new(ARG_COLLECTION_ADDRESS, CLType::ByteArray(32)),
            Parameter::new(ARG_CONTRACT_ADDRESS, CLType::ByteArray(32)),
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
    let get_action_count = EntryPoint::new(
        "get_action_count",
        vec![],
        CLType::U64,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let increment_action_count = EntryPoint::new(
        "increment_action_count",
        vec![],
        CLType::U64,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let require_enough_fees = EntryPoint::new(
        "require_enough_fees",
        vec![
            Parameter::new("data", CLType::List(Box::new(CLType::U8))),
            Parameter::new("sig_data", CLType::List(Box::new(CLType::U8))),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );
    let require_sig_verification = EntryPoint::new(
        "require_sig_verification",
        vec![
            Parameter::new("action_id", CLType::U256),
            Parameter::new("data", CLType::List(Box::new(CLType::U8))),
            Parameter::new("sig_data", CLType::List(Box::new(CLType::U8))),
            Parameter::new("context", CLType::List(Box::new(CLType::U8))),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    );

    let mut eps = EntryPoints::new();

    eps.add_entry_point(init);
    eps.add_entry_point(validate_withdraw_fees);
    eps.add_entry_point(validate_update_fee_pk);
    eps.add_entry_point(validate_update_group_key);
    eps.add_entry_point(add_contract_address);
    eps.add_entry_point(get_action_count);
    eps.add_entry_point(increment_action_count);
    eps.add_entry_point(require_enough_fees);
    eps.add_entry_point(require_sig_verification);
    eps
}

#[no_mangle]
pub extern "C" fn init() {
    if utils::named_uref_exists(INITIALIZED) {
        runtime::revert(NwlError::AlreadyInitialized);
    }
    storage::new_dictionary(KEY_CONSUMED_ACTIONS_DICT)
        .unwrap_or_revert_with(NwlError::FailedToCreateConsumedDictDictionary);
    storage::new_dictionary(CONTRACT_TO_COLLECTION_DICT)
        .unwrap_or_revert_with(NwlError::FailedToCreateContractToCollectionDict);
    storage::new_dictionary(COLLECTION_TO_CONTRACT_DICT)
        .unwrap_or_revert_with(NwlError::FailedToCollectionToContractDict);
    runtime::put_key(INITIALIZED, storage::new_uref(true).into());
}

#[no_mangle]
pub extern "C" fn call() {
    let group_key: [u8; 32] = runtime::get_named_arg(ARG_GROUP_KEY);
    let fee_public_key: [u8; 32] = runtime::get_named_arg(ARG_FEE_PUBLIC_KEY);
    let action_count: U256 = runtime::get_named_arg(ARG_ACTION_COUNT);

    let entry_points = generate_entry_points();
    let named_keys = {
        let mut named_keys = NamedKeys::new();
        named_keys.insert(INSTALLER.to_string(), runtime::get_caller().into());
        named_keys.insert(
            KEY_GROUP_KEY.to_string(),
            storage::new_uref(group_key).into(),
        );
        named_keys.insert(
            KEY_FEE_PUBLIC_KEY.to_string(),
            storage::new_uref(fee_public_key).into(),
        );
        named_keys.insert(
            KEY_ACTION_COUNT.to_string(),
            storage::new_uref(action_count).into(),
        );
        named_keys.insert(
            KEY_PURSE.to_string(),
            contract_api::system::create_purse().into(),
        );
        named_keys.insert(ACTION_COUNT.to_string(), storage::new_uref(0u64).into());
        named_keys
    };

    let hash_key_name = format!("nwl");

    let (contract_hash, _) = storage::new_contract(
        entry_points,
        Some(named_keys),
        Some(hash_key_name.clone()),
        Some(format!("no_white_list")),
    );

    let num: U512 = runtime::get_named_arg("number");

    runtime::put_key(
        &(THIS_CONTRACT.to_string() + &num.to_string()),
        contract_hash.into(),
    );
    call_contract::<()>(contract_hash, ENTRY_POINT_INIT_CONTRACT, runtime_args! {});
}
