//! Retry backoff with jitter.
//!
//! A device the platform refuses (a 403 from the provisioning hook, a rejected
//! `RegisterThing`, a refused CONNACK, a certificate set INACTIVE, the
//! quarantine group's deny-all policy) must not hammer AWS: every attempt is a
//! billable connect or message, and ten devices retrying every few seconds is
//! exactly the traffic the guard alarms watch for. So refusals back off from
//! [`REFUSED_MIN_S`] to [`REFUSED_MAX_S`], with jitter so a fleet that was cut
//! off together does not return together.
//!
//! An ordinary network failure (no route, a dropped TCP session) retries
//! quickly a few times first ([`Reconnect`]).

/// First delay after a refusal: 60 s.
pub const REFUSED_MIN_S: u64 = 60;
/// Longest delay: 6 h.
pub const REFUSED_MAX_S: u64 = 6 * 3600;
/// Delay of the first few retries after a plain network failure.
pub const QUICK_RETRY_S: u64 = 10;
/// Plain network failures retried quickly before backing off.
pub const QUICK_RETRIES: u32 = 3;
/// A connection that lasted this long was healthy: the next failure starts the
/// backoff over.
pub const HEALTHY_AFTER_S: u64 = 10 * 60;

/// Exponential backoff with "equal jitter": each delay is uniformly in
/// `[d/2, d]`, and `d` doubles up to the maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    min_s: u64,
    max_s: u64,
    next_s: u64,
}

impl Backoff {
    pub const fn new(min_s: u64, max_s: u64) -> Self {
        Self {
            min_s,
            max_s,
            next_s: min_s,
        }
    }

    /// The platform's refusal backoff, 60 s to 6 h.
    pub const fn refused() -> Self {
        Self::new(REFUSED_MIN_S, REFUSED_MAX_S)
    }

    /// The delay before the next attempt, in seconds, given a random number
    /// (the device's hardware RNG; any value works).
    pub fn next_delay_s(&mut self, random: u32) -> u64 {
        let d = self.next_s;
        let half = d / 2;
        let delay = half + u64::from(random) % (d - half + 1);
        self.next_s = (d.saturating_mul(2)).min(self.max_s);
        delay
    }

    /// Back to the first delay.
    pub fn reset(&mut self) {
        self.next_s = self.min_s;
    }
}

/// How an attempt to reach AWS IoT failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The platform said no: back off at once.
    Refused,
    /// Anything else: a few quick retries first.
    Network,
}

/// Reconnect policy for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconnect {
    quick_left: u32,
    backoff: Backoff,
}

impl Default for Reconnect {
    fn default() -> Self {
        Self::new()
    }
}

impl Reconnect {
    pub const fn new() -> Self {
        Self {
            quick_left: QUICK_RETRIES,
            backoff: Backoff::refused(),
        }
    }

    /// The delay before the next connection attempt, in seconds.
    pub fn on_failure(&mut self, failure: Failure, random: u32) -> u64 {
        if failure == Failure::Network && self.quick_left > 0 {
            self.quick_left -= 1;
            return QUICK_RETRY_S;
        }
        self.quick_left = 0;
        self.backoff.next_delay_s(random)
    }

    /// A connection stayed up for [`HEALTHY_AFTER_S`]: start over.
    pub fn on_healthy(&mut self) {
        self.quick_left = QUICK_RETRIES;
        self.backoff.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_back_off_from_a_minute_to_six_hours() {
        let mut b = Backoff::refused();
        // The highest random value gives the top of each range.
        let delays: Vec<u64> = (0..12).map(|_| b.next_delay_s(u32::MAX)).collect();
        assert!(delays[0] >= 30 && delays[0] <= 60);
        assert!(delays
            .windows(2)
            .all(|w| w[1] >= w[0] || w[1] >= REFUSED_MAX_S / 2));
        assert!(delays.iter().all(|&d| d <= REFUSED_MAX_S));
        assert!(*delays.last().unwrap() >= REFUSED_MAX_S / 2);
        b.reset();
        assert!(b.next_delay_s(0) <= 60);
    }

    #[test]
    fn jitter_stays_within_half_to_full() {
        for r in [0u32, 1, 7, 1000, u32::MAX] {
            let mut b = Backoff::new(100, 1000);
            let d = b.next_delay_s(r);
            assert!((50..=100).contains(&d), "{r}: {d}");
        }
    }

    #[test]
    fn network_failures_retry_quickly_then_back_off() {
        let mut r = Reconnect::new();
        for _ in 0..QUICK_RETRIES {
            assert_eq!(r.on_failure(Failure::Network, 0), QUICK_RETRY_S);
        }
        assert!(r.on_failure(Failure::Network, 0) >= 30);
        r.on_healthy();
        assert_eq!(r.on_failure(Failure::Network, 0), QUICK_RETRY_S);
    }

    #[test]
    fn a_refusal_skips_the_quick_retries() {
        let mut r = Reconnect::new();
        assert!(r.on_failure(Failure::Refused, 0) >= 30);
        // And a network failure right after does not get them back.
        assert!(r.on_failure(Failure::Network, 0) >= 60);
    }
}
