//! Gas costs for each transaction type.

/// Gas for a simple transfer.
pub const GAS_TRANSFER: u64 = 21_000;
/// Base gas for contract deployment.
pub const GAS_DEPLOY_BASE: u64 = 100_000;
/// Additional gas per byte of contract code.
pub const GAS_DEPLOY_PER_BYTE: u64 = 200;
/// Gas for a contract call (base).
pub const GAS_CALL_BASE: u64 = 50_000;
/// Gas for staking operations.
pub const GAS_STAKE: u64 = 30_000;
/// Gas for creating an HCS topic.
pub const GAS_CREATE_TOPIC: u64 = 50_000;
/// Gas for submitting an HCS message.
pub const GAS_TOPIC_MESSAGE: u64 = 25_000;
/// Gas for a governance vote.
pub const GAS_VOTE: u64 = 21_000;
/// Gas for validator registration.
pub const GAS_REGISTER_VALIDATOR: u64 = 100_000;

/// Gas schedule — all costs in one place.
#[derive(Clone, Debug)]
pub struct GasSchedule {
    pub transfer: u64,
    pub deploy_base: u64,
    pub deploy_per_byte: u64,
    pub call_base: u64,
    pub stake: u64,
    pub create_topic: u64,
    pub topic_message: u64,
    pub vote: u64,
    pub register_validator: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            transfer: GAS_TRANSFER,
            deploy_base: GAS_DEPLOY_BASE,
            deploy_per_byte: GAS_DEPLOY_PER_BYTE,
            call_base: GAS_CALL_BASE,
            stake: GAS_STAKE,
            create_topic: GAS_CREATE_TOPIC,
            topic_message: GAS_TOPIC_MESSAGE,
            vote: GAS_VOTE,
            register_validator: GAS_REGISTER_VALIDATOR,
        }
    }
}
