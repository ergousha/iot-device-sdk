//! The on-device publish limiter: runaway firmware is stopped before AWS
//! bills it.
//!
//! Every publish of a device, every topic included, passes [`Limiter::admit`]:
//! at most [`Limits::publishes_per_minute`] in any rolling 60 s, and none
//! larger than [`Limits::max_message_bytes`]. The cloud's alarms and kill
//! switch stay the backstop; this is the first line, and it costs nothing.
//!
//! Time is passed in, in milliseconds since any fixed point, so the logic is
//! tested on the host.

use std::collections::VecDeque;

use crate::product::Limits;

const WINDOW_MS: u64 = 60_000;

/// Why a publish was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The payload is over the size limit.
    TooLarge { bytes: usize, max: usize },
    /// The rolling-minute budget is spent; `retry_in_ms` until a slot frees.
    RateLimited { retry_in_ms: u64 },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(f, "payload of {bytes} B is over the {max} B limit")
            }
            Self::RateLimited { retry_in_ms } => write!(
                f,
                "publish limit reached; next slot in {} s",
                retry_in_ms.div_ceil(1000)
            ),
        }
    }
}

/// A rolling-window publish limiter.
#[derive(Debug, Clone)]
pub struct Limiter {
    limits: Limits,
    /// When each publish of the last minute was admitted.
    sent: VecDeque<u64>,
    /// Refusals since the last one was logged, for a quiet log.
    refused: u32,
}

impl Limiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            sent: VecDeque::new(),
            refused: 0,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Admits a publish of `bytes` at `now_ms`, and counts it; or says why
    /// not. A refused publish is not counted.
    pub fn admit(&mut self, bytes: usize, now_ms: u64) -> Result<(), Refusal> {
        if bytes > self.limits.max_message_bytes {
            self.refused += 1;
            return Err(Refusal::TooLarge {
                bytes,
                max: self.limits.max_message_bytes,
            });
        }
        while self
            .sent
            .front()
            .is_some_and(|&t| now_ms.saturating_sub(t) >= WINDOW_MS)
        {
            self.sent.pop_front();
        }
        if self.sent.len() >= self.limits.publishes_per_minute as usize {
            self.refused += 1;
            let oldest = *self.sent.front().expect("non-empty when full");
            return Err(Refusal::RateLimited {
                retry_in_ms: WINDOW_MS - now_ms.saturating_sub(oldest),
            });
        }
        self.sent.push_back(now_ms);
        Ok(())
    }

    /// Publishes left in the current window at `now_ms`.
    pub fn available(&self, now_ms: u64) -> u32 {
        let used = self
            .sent
            .iter()
            .filter(|&&t| now_ms.saturating_sub(t) < WINDOW_MS)
            .count() as u32;
        self.limits.publishes_per_minute.saturating_sub(used)
    }

    /// Refusals since the last call, which resets the count.
    pub fn take_refused(&mut self) -> u32 {
        std::mem::take(&mut self.refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(per_minute: u32) -> Limiter {
        Limiter::new(Limits {
            publishes_per_minute: per_minute,
            max_message_bytes: 5120,
        })
    }

    #[test]
    fn at_most_n_publishes_in_any_minute() {
        let mut l = limiter(3);
        for t in [0, 10, 20] {
            l.admit(10, t).unwrap();
        }
        assert_eq!(
            l.admit(10, 30),
            Err(Refusal::RateLimited {
                retry_in_ms: 59_970
            })
        );
        assert_eq!(l.available(30), 0);
        // The first slot frees exactly a minute after it was used.
        assert!(l.admit(10, 59_999).is_err());
        l.admit(10, 60_000).unwrap();
        assert!(l.admit(10, 60_005).is_err());
        assert_eq!(l.take_refused(), 3);
        assert_eq!(l.take_refused(), 0);
    }

    #[test]
    fn a_steady_trickle_is_never_refused() {
        let mut l = limiter(10);
        for i in 0..1000u64 {
            l.admit(100, i * 6_000).unwrap();
        }
    }

    #[test]
    fn oversized_payloads_are_refused_and_not_counted() {
        let mut l = limiter(1);
        assert_eq!(
            l.admit(5121, 0),
            Err(Refusal::TooLarge {
                bytes: 5121,
                max: 5120
            })
        );
        l.admit(5120, 0).unwrap();
    }

    #[test]
    fn refusals_read_well() {
        assert_eq!(
            Refusal::RateLimited { retry_in_ms: 1500 }.to_string(),
            "publish limit reached; next slot in 2 s"
        );
    }
}
