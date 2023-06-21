#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

extern crate alloc;
use alloc::string::String;

use casper_contract::contract_api::{account, runtime};
use casper_types::{runtime_args, ContractHash, Key, RuntimeArgs, U512};

use crate::tid::TokenIdentifier;
mod tid;

const ARG_MINT_WITH: &str = "mint_with";
const ARG_CONTRACT: &str = "contract";
const ARG_CHAIN_NONCE: &str = "chain_nonce";
const ARG_TOKEN_ID: &str = "token_id";
const ARG_BRIDGE_CONTRACT_HASH: &str = "bridge_contract";
const ARG_TO: &str = "to";
const ARG_AMOUNT: &str = "amount";
const ARG_SIG_DATA: &str = "sig_data";
const ARG_SENDER_PURSE: &str = "sender_purse";

#[no_mangle]
pub extern "C" fn call() {
    let nft_contract_hash: ContractHash = runtime::get_named_arg::<Key>(ARG_BRIDGE_CONTRACT_HASH)
        .into_hash()
        .map(ContractHash::new)
        .unwrap();

    let contract: ContractHash = runtime::get_named_arg(ARG_CONTRACT);
    let token_id: TokenIdentifier = runtime::get_named_arg(ARG_TOKEN_ID);
    let to: String = runtime::get_named_arg(ARG_TO);
    let mint_with: String = runtime::get_named_arg(ARG_MINT_WITH);
    let chain_nonce: u8 = runtime::get_named_arg(ARG_CHAIN_NONCE);
    let amount: U512 = runtime::get_named_arg(ARG_AMOUNT);
    let sig_data: [u8; 64] = runtime::get_named_arg(ARG_SIG_DATA);

    const ENTRY_POINT_FREEZE_NFT: &str = "freeze_nft";
    runtime::call_contract::<()>(
        nft_contract_hash,
        ENTRY_POINT_FREEZE_NFT,
        runtime_args! {
            ARG_CONTRACT => contract,
            ARG_TOKEN_ID => token_id,
            ARG_TO => to,
            ARG_MINT_WITH => mint_with,
            ARG_CHAIN_NONCE => chain_nonce,
            ARG_AMOUNT => amount,
            ARG_SIG_DATA => sig_data,
            ARG_SENDER_PURSE => account::get_main_purse()
        },
    );
}
