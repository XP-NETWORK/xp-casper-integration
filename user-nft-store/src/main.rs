#![no_std]
#![no_main]

use alloc::vec;
use alloc::{
    format,
    string::{String, ToString},
};
use casper_contract::contract_api::system::transfer_from_purse_to_account;
use casper_contract::{
    contract_api::{self, runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::account::AccountHash;
use casper_types::{
    bytesrepr::serialize, contracts::NamedKeys, CLType, ContractHash, EntryPoint, EntryPointAccess,
    EntryPointType, EntryPoints, Key, Parameter, URef, U256, U512,
};

use errors::UserNftStoreError;
use external::nwl;

use constants::*;
use events::TransferNftEvent;
use external::xp_nft::{self, TokenIdentifier};
use structs::{FreezeNFT, TxFee, ValidateUnfreezeData};

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

mod constants;
mod errors;
mod events;
mod external;
mod structs;
mod utils;

pub extern "C" fn freeze_nft() {
    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        UserNftStoreError::MissingArgumentContract,
        UserNftStoreError::InvalidArgumentContract,
    )
    .unwrap_or_revert();

    let token_id: TokenIdentifier = utils::get_named_arg_with_user_errors(
        ARG_TOKEN_ID,
        UserNftStoreError::MissingArgumentTokenID,
        UserNftStoreError::InvalidArgumentTokenID,
    )
    .unwrap_or_revert();
    let to: String = utils::get_named_arg_with_user_errors(
        ARG_TO,
        UserNftStoreError::MissingArgumentTo,
        UserNftStoreError::InvalidArgumentTo,
    )
    .unwrap_or_revert();
    let mint_with: String = utils::get_named_arg_with_user_errors(
        ARG_MINT_WITH,
        UserNftStoreError::MissingArgumentMintWith,
        UserNftStoreError::InvalidArgumentMintWith,
    )
    .unwrap_or_revert();

    let chain_nonce: u8 = utils::get_named_arg_with_user_errors(
        ARG_CHAIN_NONCE,
        UserNftStoreError::MissingArgumentChainNonce,
        UserNftStoreError::InvalidArgumentChainNonce,
    )
    .unwrap_or_revert();
    let amt: U512 = utils::get_named_arg_with_user_errors(
        ARG_AMOUNT,
        UserNftStoreError::MissingArgumentAmount,
        UserNftStoreError::InvalidArgumentAmount,
    )
    .unwrap_or_revert();
    let sig_data: [u8; 64] = utils::get_named_arg_with_user_errors(
        ARG_SIG_DATA,
        UserNftStoreError::MissingArgumentSigData,
        UserNftStoreError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let sender_purse: URef = utils::get_named_arg_with_user_errors(
        ARG_SENDER_PURSE,
        UserNftStoreError::MissingArgumentSigData,
        UserNftStoreError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let nwl = get_no_whitelist();

    let increment = nwl::increment_action_count(nwl);

    if !increment {
        runtime::revert(UserNftStoreError::FailedToIncrementActionCount);
    }

    let action_id = nwl::get_action_count(nwl);

    let data = FreezeNFT {
        amt,
        chain_nonce,
        contract,
        mint_with,
        sig_data,
        token_id,
        to,
    };
    let meta = xp_nft::metadata(data.contract, data.token_id.clone());
    nwl::require_enough_fees(
        nwl,
        serialize(TxFee {
            from: 39,
            to: data.chain_nonce,
            receiver: data.to.clone(),
            value: data.amt,
        })
        .unwrap_or_revert_with(UserNftStoreError::FailedToSerializeTxFee),
        &data.sig_data,
    );

    transfer_tx_fees(data.amt, sender_purse);

    xp_nft::transfer(
        data.contract,
        runtime::get_caller().into(),
        get_contract_hash().into(),
        data.token_id.clone(),
    );

    let ev = TransferNftEvent {
        action_id,
        amt: data.amt,
        chain_nonce: data.chain_nonce,
        to: data.to,
        contract: data.contract.to_string(),
        token_id: data.token_id,
        mint_with: data.mint_with,
        metadata: meta,
    };
    casper_event_standard::emit(ev);
}

pub fn get_contract_hash() -> ContractHash {
    contract_api::runtime::get_call_stack()
        .iter()
        .nth_back(0)
        .unwrap_or_revert_with(UserNftStoreError::FailedToGetCallStack)
        .contract_hash()
        .unwrap_or_revert_with(UserNftStoreError::FailedToParseContractHash)
        .clone()
}

pub fn get_receiver_acc_hash() -> AccountHash {
    let receiver_uref = utils::get_uref(
        RECEIVER_ACC_HASH,
        UserNftStoreError::MissingReceiverAccountHash,
        UserNftStoreError::InvalidReceiverAccountHash,
    );
    let receiver_acc_hash: AccountHash = storage::read_or_revert(receiver_uref);
    receiver_acc_hash
}

pub fn transfer_tx_fees(amount: U512, sender_purse: URef) {
    transfer_from_purse_to_account(sender_purse, get_receiver_acc_hash(), amount, None)
        .unwrap_or_revert();
}

#[no_mangle]
pub extern "C" fn validate_unfreeze_nft() {
    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        UserNftStoreError::MissingArgumentContract,
        UserNftStoreError::InvalidArgumentContract,
    )
    .unwrap_or_revert();

    let receiver: Key = utils::get_named_arg_with_user_errors(
        ARG_RECEIVER,
        UserNftStoreError::MissingArgumentReceiver,
        UserNftStoreError::InvalidArgumentReceiver,
    )
    .unwrap_or_revert();

    let token_id: TokenIdentifier = utils::get_named_arg_with_user_errors(
        ARG_TOKEN_ID,
        UserNftStoreError::MissingArgumentTokenID,
        UserNftStoreError::InvalidArgumentTokenID,
    )
    .unwrap_or_revert();
    let action_id: U256 = utils::get_named_arg_with_user_errors(
        ARG_ACTION_ID,
        UserNftStoreError::MissingArgumentActionID,
        UserNftStoreError::InvalidArgumentActionID,
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
        UserNftStoreError::MissingArgumentSigData,
        UserNftStoreError::InvalidArgumentSigData,
    )
    .unwrap_or_revert();

    let nwl = get_no_whitelist();

    nwl::require_sig_verification(
        nwl,
        action_id,
        serialize(data.clone())
            .unwrap_or_revert_with(UserNftStoreError::FailedToSerializeActionStruct),
        &sig_data,
        b"ValidateUnfreezeNft",
    );

    xp_nft::transfer(
        data.contract,
        get_contract_hash().into(),
        data.receiver,
        data.token_id,
    );
}
pub fn get_group_key() -> [u8; 32] {
    let gk_uref = utils::get_uref(
        KEY_GROUP_KEY,
        UserNftStoreError::MissingGroupKeyUref,
        UserNftStoreError::InvalidGroupKeyUref,
    );

    let group_key: [u8; 32] = storage::read_or_revert(gk_uref);
    group_key
}

pub fn get_no_whitelist() -> ContractHash {
    let nwl_uref = utils::get_uref(
        KEY_NWL,
        UserNftStoreError::MissingGroupKeyUref,
        UserNftStoreError::InvalidGroupKeyUref,
    );

    let nwl: ContractHash = storage::read_or_revert(nwl_uref);
    nwl
}

fn create_entrypoints() -> EntryPoints {
    let mut entry_points = EntryPoints::new();

    entry_points.add_entry_point(EntryPoint::new(
        "freeze_nft",
        vec![
            Parameter::new(ARG_CONTRACT, CLType::ByteArray(32)),
            Parameter::new(ARG_TOKEN_ID, CLType::String),
            Parameter::new(ARG_TO, CLType::String),
            Parameter::new(ARG_MINT_WITH, CLType::String),
            Parameter::new(ARG_CHAIN_NONCE, CLType::U8),
            Parameter::new(ARG_AMOUNT, CLType::U512),
            Parameter::new(ARG_SIG_DATA, CLType::ByteArray(64)),
            Parameter::new(ARG_SENDER_PURSE, CLType::URef),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));
    entry_points.add_entry_point(EntryPoint::new(
        "validate_unfreeze_nft",
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
    ));

    entry_points
}

#[no_mangle]
pub extern "C" fn call() {
    let entry_points = create_entrypoints();
    let named_keys = {
        let mut named_keys = NamedKeys::new();
        named_keys.insert(INSTALLER.to_string(), runtime::get_caller().into());

        named_keys
    };

    let receiver_account_hash: AccountHash = utils::get_named_arg_with_user_errors("receiver_account_hash", UserNftStoreError::MissingReceiverAccountHash, UserNftStoreError::InvalidReceiverAccountHash).unwrap_or_revert();
    let no_white_list: ContractHash = utils::get_named_arg_with_user_errors("no_whitelist_contract", UserNftStoreError::MissingNoWhitelistContract, UserNftStoreError::InvalidNoWhitelistContract).unwrap_or_revert();

    runtime::put_key("key_receiver_account_hash", storage::new_uref(receiver_account_hash).into());
    runtime::put_key("key_no_white_list", storage::new_uref(no_white_list).into());


    let contract: ContractHash = utils::get_named_arg_with_user_errors(
        ARG_CONTRACT,
        UserNftStoreError::MissingArgumentContract,
        UserNftStoreError::InvalidArgumentContract,
    )
    .unwrap_or_revert();

    let hash_key_name = format!("freezer_{contract}");
    let access_key_name = format!("freezer_access_{contract}");

    let (contract_hash, _) = storage::new_contract(
        entry_points,
        Some(named_keys),
        Some(hash_key_name),
        Some(access_key_name),
    );

    runtime::put_key(THIS_CONTRACT, contract_hash.into());
}
