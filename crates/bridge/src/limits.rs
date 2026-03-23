//! Bridge safety limits — caps, cooldowns, and emergency pause.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6

use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

/// Approximate blocks per day (at 3-second block time).
const BLOCKS_PER_DAY: u64 = 28_800;

/// Bridge safety limit configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeLimits {
    /// Maximum total volume per day.
    pub daily_volume_cap: TokenAmount,
    /// Maximum amount per single bridge transaction.
    pub per_tx_max: TokenAmount,
    /// Minimum amount per single bridge transaction.
    pub per_tx_min: TokenAmount,
    /// Minimum blocks between bridge transactions from the same sender.
    pub cooldown_blocks: u64,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            daily_volume_cap: TokenAmount::from_tokens(10_000_000), // 10M CATH/day
            per_tx_max: TokenAmount::from_tokens(1_000_000),        // 1M CATH
            per_tx_min: TokenAmount::from_tokens(1),                // 1 CATH
            cooldown_blocks: 10,                                     // ~30 seconds
        }
    }
}

/// Errors from the limit tracker.
#[derive(Debug, thiserror::Error)]
pub enum LimitError {
    #[error("bridge is paused")]
    BridgePaused,
    #[error("amount {0} below per-tx minimum {1}")]
    BelowMinimum(TokenAmount, TokenAmount),
    #[error("amount {0} above per-tx maximum {1}")]
    AboveMaximum(TokenAmount, TokenAmount),
    #[error("daily volume cap exceeded: used {used}, cap {cap}, requested {requested}")]
    DailyCapExceeded {
        used: TokenAmount,
        cap: TokenAmount,
        requested: TokenAmount,
    },
    #[error("cooldown active: last transfer at block {last}, current {current}, need {cooldown} blocks")]
    CooldownActive {
        last: u64,
        current: u64,
        cooldown: u64,
    },
    #[error("arithmetic overflow")]
    Overflow,
    #[error("caller {0} is not the admin")]
    Unauthorized(Address),
}

/// Tracks daily volume and enforces limits.
pub struct LimitTracker {
    limits: BridgeLimits,
    emergency_pause: AtomicBool,
    /// Admin address that can pause/unpause/reset.
    admin: Address,
    /// Current day's volume and the block that started this day.
    state: Mutex<DayState>,
    /// Per-sender cooldown tracking.
    sender_last_block: DashMap<Address, u64>,
}

struct DayState {
    day_start_block: u64,
    volume_used: TokenAmount,
}

impl LimitTracker {
    /// Create a new limit tracker with default limits and the given admin.
    pub fn new(admin: Address) -> Self {
        Self::with_limits(BridgeLimits::default(), admin)
    }

    /// Create with custom limits and admin.
    pub fn with_limits(limits: BridgeLimits, admin: Address) -> Self {
        Self {
            limits,
            emergency_pause: AtomicBool::new(false),
            admin,
            state: Mutex::new(DayState {
                day_start_block: 0,
                volume_used: TokenAmount::ZERO,
            }),
            sender_last_block: DashMap::new(),
        }
    }

    /// Track a bridge transfer, enforcing all limits.
    /// Cooldown is enforced per sender.
    pub fn track_transfer(
        &self,
        sender: Address,
        amount: TokenAmount,
        current_block: u64,
    ) -> Result<(), LimitError> {
        // Emergency pause check
        if self.is_paused() {
            return Err(LimitError::BridgePaused);
        }

        // Per-tx min/max
        if amount < self.limits.per_tx_min {
            return Err(LimitError::BelowMinimum(amount, self.limits.per_tx_min));
        }
        if amount > self.limits.per_tx_max {
            return Err(LimitError::AboveMaximum(amount, self.limits.per_tx_max));
        }

        // Per-sender cooldown check
        if let Some(last_block) = self.sender_last_block.get(&sender) {
            let blocks_since = current_block.saturating_sub(*last_block);
            if blocks_since < self.limits.cooldown_blocks {
                return Err(LimitError::CooldownActive {
                    last: *last_block,
                    current: current_block,
                    cooldown: self.limits.cooldown_blocks,
                });
            }
        }

        let mut state = self.state.lock();

        // Security fix: use block-number aligned day boundaries instead of
        // resetting day_start_block to current_block.
        //
        // Previous behaviour:  day_start_block = current_block on every reset.
        // Attack:  submit TX at block 28799 (just before reset), then again at
        //          block 28800 (triggers reset to 28800), effectively getting
        //          2× daily_volume_cap within a single natural day.
        //
        // Fix:  align to the fixed grid  floor(current_block / BLOCKS_PER_DAY)
        //       so the day boundary is always at a multiple of BLOCKS_PER_DAY
        //       regardless of when the first transfer of a new period arrives.
        //       An attacker can no longer shift the window by timing their calls.
        // Signed-off-by: Claude Opus 4.6
        let current_day_start = (current_block / BLOCKS_PER_DAY) * BLOCKS_PER_DAY;
        if current_day_start != state.day_start_block {
            state.day_start_block = current_day_start;
            state.volume_used = TokenAmount::ZERO;
        }

        // Daily cap check
        let new_volume = state.volume_used.checked_add(amount)
            .ok_or(LimitError::Overflow)?;
        if new_volume > self.limits.daily_volume_cap {
            return Err(LimitError::DailyCapExceeded {
                used: state.volume_used,
                cap: self.limits.daily_volume_cap,
                requested: amount,
            });
        }

        state.volume_used = new_volume;
        // Update per-sender cooldown
        self.sender_last_block.insert(sender, current_block);
        Ok(())
    }

    /// Manually reset the daily volume counter. Requires admin.
    ///
    /// `block` is aligned to the BLOCKS_PER_DAY grid so the manual reset
    /// cannot introduce a window misalignment that would let the next automatic
    /// reset fire early or late.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn reset_daily(&self, block: u64, caller: Address) -> Result<(), LimitError> {
        if caller != self.admin {
            return Err(LimitError::Unauthorized(caller));
        }
        let mut state = self.state.lock();
        // Align to grid — same formula as track_transfer.
        state.day_start_block = (block / BLOCKS_PER_DAY) * BLOCKS_PER_DAY;
        state.volume_used = TokenAmount::ZERO;
        Ok(())
    }

    /// Is the bridge in emergency pause?
    pub fn is_paused(&self) -> bool {
        self.emergency_pause.load(Ordering::SeqCst)
    }

    /// Trigger emergency pause. Requires admin.
    pub fn pause(&self, caller: Address) -> Result<(), LimitError> {
        if caller != self.admin {
            return Err(LimitError::Unauthorized(caller));
        }
        self.emergency_pause.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Resume from emergency pause. Requires admin.
    pub fn unpause(&self, caller: Address) -> Result<(), LimitError> {
        if caller != self.admin {
            return Err(LimitError::Unauthorized(caller));
        }
        self.emergency_pause.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Get the current limits configuration.
    pub fn limits(&self) -> &BridgeLimits {
        &self.limits
    }

    /// Get current daily volume used.
    pub fn daily_volume_used(&self) -> TokenAmount {
        self.state.lock().volume_used
    }
}
