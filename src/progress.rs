//! A small, dependency-free progress bar rendered on stderr.
//!
//! Only draws when enabled and stderr is a terminal, so piping output or the
//! `--dry-run` stdout stream stays clean. Use [`Progress::note`] to print a
//! message without clobbering the in-place bar.

use std::io::{IsTerminal, Write, stderr};

pub struct Progress {
    total: usize,
    done: usize,
    /// Draw the live bar (enabled by caller and stderr is a TTY).
    live: bool,
}

const BAR_WIDTH: usize = 24;
/// Truncate the trailing label to keep the line from wrapping.
const LABEL_MAX: usize = 40;

impl Progress {
    pub fn new(total: usize, enabled: bool) -> Self {
        Self {
            total,
            done: 0,
            live: enabled && stderr().is_terminal(),
        }
    }

    /// Advance by one and redraw the bar with `label` as the current item.
    pub fn tick(&mut self, label: &str) {
        if self.done < self.total {
            self.done += 1;
        }
        self.render(label);
    }

    /// Print a standalone message above the bar (clearing it first).
    pub fn note(&mut self, msg: &str) {
        if self.live {
            // Carriage return + clear-to-end-of-line, then the message.
            let _ = write!(stderr(), "\r\x1b[2K");
        }
        eprintln!("{msg}");
    }

    /// Move the cursor off the bar once the run is complete.
    pub fn finish(&mut self) {
        if self.live {
            let _ = write!(stderr(), "\r\x1b[2K");
            let _ = stderr().flush();
        }
    }

    fn render(&self, label: &str) {
        if !self.live || self.total == 0 {
            return;
        }
        let filled = BAR_WIDTH * self.done / self.total;
        let bar: String = "█".repeat(filled) + &"░".repeat(BAR_WIDTH - filled);
        let pct = self.done * 100 / self.total;
        let label = truncate(label, LABEL_MAX);
        // Right-align `done` to the width of `total` so the bar doesn't shift
        // as the count grows from 1 to 2 to 3 digits.
        let width = self.total.to_string().len();
        let _ = write!(
            stderr(),
            "\r\x1b[2K[{bar}] {done:>width$}/{total} ({pct:>3}%)  {label}",
            done = self.done,
            total = self.total,
        );
        let _ = stderr().flush();
    }
}

/// Truncate to `max` characters (by char, not byte), adding an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_does_not_exceed_total() {
        let mut p = Progress::new(2, false);
        p.tick("a");
        p.tick("b");
        p.tick("c"); // extra tick is clamped
        assert_eq!(p.done, 2);
    }

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("logins/x", 40), "logins/x");
        assert_eq!(truncate(&"a".repeat(50), 10).chars().count(), 10);
    }
}
