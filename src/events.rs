use alloc::string::String;
use casper_event_standard::Event;
use casper_types::U256;

#[derive(Clone, Event, Debug)]
pub struct TransferNftEvent {
    pub chain_nonce: u8,
    pub to: String,
    pub mint_with: String,
    pub amt: U256,
    pub action_id: U256,
    pub token_id: String,
    pub contract: String,
}

#[derive(Clone, Event, Debug)]
pub struct UnfreezeNftEvent {
    pub chain_nonce: u8,
    pub to: String,
    pub amt: U256,
    pub action_id: U256,
    pub token_id: String,
    pub contract: String,
}
