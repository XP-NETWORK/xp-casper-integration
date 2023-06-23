#![allow(dead_code)]
pub mod xp_nft {
    use alloc::string::String;
    use casper_contract::contract_api::runtime;
    use casper_types::{runtime_args, ContractHash, Key, RuntimeArgs};

    #[derive(PartialEq, Eq, Clone, Debug)]
    pub enum TokenIdentifier {
        Index(u64),
        Hash(String),
    }

    const ENTRY_POINT_MINT: &str = "mint";

    const ARG_TOKEN_OWNER: &str = "token_owner";
    const ARG_TOKEN_META_DATA: &str = "token_meta_data";
    const ARG_TOKEN_ID: &str = "token_id";
    const ARG_TOKEN_HASH: &str = "token_hash";
    const ENTRY_POINT_BURN: &str = "burn";
    const ARG_TARGET_KEY: &str = "target_key";
    const ARG_SOURCE_KEY: &str = "source_key";
    const ENTRY_POINT_TRANSFER: &str = "transfer";
    const ENTRY_POINT_METADATA: &str = "metadata";

    pub fn mint(nft_contract: ContractHash, token_owner: Key, token_metadata: String) {
        runtime::call_contract::<()>(
            nft_contract,
            ENTRY_POINT_MINT,
            runtime_args! {
                ARG_TOKEN_OWNER => token_owner,
                ARG_TOKEN_META_DATA => token_metadata,
            },
        );
    }

    pub fn metadata(nft_contract: ContractHash, tid: TokenIdentifier) -> String {
        let (meta,) = match tid {
            TokenIdentifier::Index(token_idx) => runtime::call_contract::<(String,)>(
                nft_contract,
                ENTRY_POINT_METADATA,
                runtime_args! {
                ARG_TOKEN_ID => token_idx,
                                },
            ),
            TokenIdentifier::Hash(token_hash) => runtime::call_contract::<(String,)>(
                nft_contract,
                ENTRY_POINT_METADATA,
                runtime_args! {
                ARG_TOKEN_HASH => token_hash,
                                },
            ),
        };
        meta
    }

    pub fn burn(nft_contract: ContractHash, tid: TokenIdentifier) {
        match tid {
            TokenIdentifier::Index(token_idx) => runtime::call_contract::<()>(
                nft_contract,
                ENTRY_POINT_BURN,
                runtime_args! {
                    ARG_TOKEN_ID => token_idx,
                },
            ),
            TokenIdentifier::Hash(token_hash) => runtime::call_contract::<()>(
                nft_contract,
                ENTRY_POINT_BURN,
                runtime_args! {
                    ARG_TOKEN_HASH => token_hash,
                },
            ),
        };
    }

    pub fn transfer(
        nft_contract: ContractHash,
        source_key: Key,
        target_key: Key,
        tid: TokenIdentifier,
    ) {
        match tid {
            TokenIdentifier::Index(idx) => runtime::call_contract::<()>(
                nft_contract,
                ENTRY_POINT_TRANSFER,
                runtime_args! {
                    ARG_TOKEN_ID => idx,
                    ARG_TARGET_KEY => target_key,
                    ARG_SOURCE_KEY => source_key
                },
            ),
            TokenIdentifier::Hash(token_hash) => runtime::call_contract::<()>(
                nft_contract,
                ENTRY_POINT_TRANSFER,
                runtime_args! {
                    ARG_TOKEN_HASH => token_hash,
                    ARG_TARGET_KEY => target_key,
                    ARG_SOURCE_KEY => source_key
                },
            ),
        };
    }
}
