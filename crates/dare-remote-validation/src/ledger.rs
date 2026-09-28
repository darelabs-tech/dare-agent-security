//! The output ledger: every byte written for a run is scrubbed and counted
//! before it is written (BLUEPRINT §4, "scrub + output ledger admit before
//! every write").

use crate::credential::Scrubber;
use crate::error::{RemoteError, Result};
use crate::limits::MAX_OUTPUT_BYTES;

pub struct OutputLedger {
    scrubber: Scrubber,
    used: usize,
    max: usize,
}

impl OutputLedger {
    pub fn new(scrubber: Scrubber) -> OutputLedger {
        OutputLedger {
            scrubber,
            used: 0,
            max: MAX_OUTPUT_BYTES,
        }
    }

    #[cfg(any(test, feature = "lab"))]
    pub fn with_max(scrubber: Scrubber, max: usize) -> OutputLedger {
        OutputLedger {
            scrubber,
            used: 0,
            max,
        }
    }

    /// Scrub `bytes` and charge them. The scrubbed bytes are what may be
    /// written; nothing is charged when the budget would be exceeded.
    pub fn admit(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let (scrubbed, _, _) = self.scrubber.scrub(bytes);
        let next = self
            .used
            .checked_add(scrubbed.len())
            .ok_or(RemoteError::OutputBudgetExceeded)?;
        if next > self.max {
            return Err(RemoteError::OutputBudgetExceeded);
        }
        self.used = next;
        Ok(scrubbed)
    }

    /// Charge bytes written to a scratch area that is never published (the
    /// A2A work directory).
    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        let next = self
            .used
            .checked_add(bytes)
            .ok_or(RemoteError::OutputBudgetExceeded)?;
        if next > self.max {
            return Err(RemoteError::OutputBudgetExceeded);
        }
        self.used = next;
        Ok(())
    }

    pub fn used(&self) -> usize {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_bytes_are_scrubbed_and_counted() {
        let mut ledger = OutputLedger::with_max(Scrubber::new(None), 1_000);
        let token = ["gh", "p_0123456789abcdefghijABCD"].concat();
        let out = ledger.admit(format!("x {token} y").as_bytes()).unwrap();
        assert!(!String::from_utf8_lossy(&out).contains(&token));
        assert_eq!(ledger.used(), out.len());
    }

    #[test]
    fn the_write_that_would_exceed_the_budget_is_refused_and_not_charged() {
        let mut ledger = OutputLedger::with_max(Scrubber::new(None), 10);
        ledger.admit(b"12345678").unwrap();
        assert!(matches!(
            ledger.admit(b"abc"),
            Err(RemoteError::OutputBudgetExceeded)
        ));
        assert_eq!(ledger.used(), 8);
        assert!(matches!(
            ledger.charge(3),
            Err(RemoteError::OutputBudgetExceeded)
        ));
        ledger.charge(2).unwrap();
    }
}
