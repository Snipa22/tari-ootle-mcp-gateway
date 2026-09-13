//! Sliding-window transaction rate limiter.
//!
//! Ported from `tari-project/universe`'s `src-tauri/src/mcp/rate_limiter.rs` (read fresh
//! from a clone of that repo this session, not guessed). The real logic is a sliding
//! window over the last 60 seconds, not a token bucket — confirmed by reading the actual
//! source rather than assuming, since AGENTS.md explicitly did not specify which of the two
//! it was.
//!
//! Adapted for a standalone (non-Tauri) binary: Universe's version reads its per-minute
//! limit from `ConfigMcp::content().await` (a Tauri-app-wide config singleton this repo has
//! no equivalent of). Here the limit is a plain constructor argument so the caller (the
//! future `mcp::server`/`ootle_transact` module, per AGENTS.md's v1 build order — not built
//! in this dispatch) can wire it up however it ends up sourcing config (env var / CLI flag,
//! same resolution order as the rest of this repo's config).

use std::{collections::VecDeque, time::Instant};

pub struct TransactionRateLimiter {
    timestamps: VecDeque<Instant>,
    limit_per_minute: u32,
}

impl TransactionRateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            timestamps: VecDeque::new(),
            limit_per_minute,
        }
    }

    /// Check if a transaction is allowed under the sliding window rate limit.
    /// Returns `true` if the transaction is within the configured limit per minute.
    pub fn check_transaction_allowed(&mut self) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        // Remove expired entries
        while self
            .timestamps
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            self.timestamps.pop_front();
        }

        if self.timestamps.len() >= self.limit_per_minute as usize {
            return false;
        }

        self.timestamps.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn new_limiter_has_no_timestamps() {
        let limiter = TransactionRateLimiter::new(5);
        assert!(limiter.timestamps.is_empty());
    }

    #[test]
    fn new_limiter_deque_length_is_zero() {
        let limiter = TransactionRateLimiter::new(5);
        assert_eq!(limiter.timestamps.len(), 0);
    }

    #[test]
    fn sliding_window_removes_expired_entries() {
        let mut limiter = TransactionRateLimiter::new(5);
        // Insert a timestamp that is more than 60 seconds old
        let expired = Instant::now() - Duration::from_secs(120);
        limiter.timestamps.push_back(expired);
        assert_eq!(limiter.timestamps.len(), 1);

        // A fresh check should evict the expired entry and then admit the new one.
        assert!(limiter.check_transaction_allowed());
        assert_eq!(limiter.timestamps.len(), 1);
    }

    #[test]
    fn sliding_window_keeps_fresh_entries() {
        let mut limiter = TransactionRateLimiter::new(5);
        let fresh = Instant::now();
        limiter.timestamps.push_back(fresh);

        assert!(limiter.check_transaction_allowed());
        assert_eq!(
            limiter.timestamps.len(),
            2,
            "Fresh timestamp plus the new admission"
        );
    }

    #[test]
    fn window_check_with_mixed_entries() {
        let mut limiter = TransactionRateLimiter::new(5);
        // Two expired, one fresh
        limiter
            .timestamps
            .push_back(Instant::now() - Duration::from_secs(120));
        limiter
            .timestamps
            .push_back(Instant::now() - Duration::from_secs(90));
        limiter.timestamps.push_back(Instant::now());

        assert!(limiter.check_transaction_allowed());
        assert_eq!(
            limiter.timestamps.len(),
            2,
            "Only the fresh entry plus the new admission should remain"
        );
    }

    #[test]
    fn limit_check_blocks_when_at_capacity() {
        let mut limiter = TransactionRateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.check_transaction_allowed());
        }
        assert!(
            !limiter.check_transaction_allowed(),
            "6th call within the window should be blocked at limit=5"
        );
    }

    #[test]
    fn limit_check_allows_when_below_capacity() {
        let mut limiter = TransactionRateLimiter::new(5);
        for _ in 0..4 {
            assert!(limiter.check_transaction_allowed());
        }
        assert!(
            limiter.check_transaction_allowed(),
            "5th call within the window should still be allowed at limit=5"
        );
    }

    #[test]
    fn zero_limit_blocks_everything() {
        let mut limiter = TransactionRateLimiter::new(0);
        assert!(!limiter.check_transaction_allowed());
    }
}
