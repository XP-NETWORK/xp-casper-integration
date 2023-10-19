use alloc::string::String;
use casper_event_standard::Event;
use casper_types::U512;

use crate::external::xp_nft::TokenIdentifier;


#[derive(Clone, Event, Debug)]
pub struct TransferNftEvent {
    pub action_id: u64,
    pub chain_nonce: u8,
    pub to: String,
    pub mint_with: String,
    pub amt: U512,
    pub token_id: TokenIdentifier,
    pub contract: String,
    pub metadata: String,
}