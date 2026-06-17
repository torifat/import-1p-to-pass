//! Slugify titles into safe pass entry/path segments, and track collisions.

use std::collections::HashSet;

/// Turn an arbitrary title into a single safe path segment.
///
/// Keeps it human-readable: lowercases, replaces whitespace and path
/// separators with `-`, drops other punctuation, collapses repeats.
/// Empty input becomes `untitled`.
pub fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_dash = false;
    for ch in input.trim().chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if ch == '.' || ch == '_' {
            Some(ch)
        } else if ch.is_whitespace() || ch == '/' || ch == '\\' {
            Some('-')
        } else {
            // Drop other punctuation, but treat it as a separator so
            // "foo&bar" -> "foo-bar" rather than "foobar".
            Some('-')
        };
        match mapped {
            Some('-') => {
                if !prev_dash && !out.is_empty() {
                    out.push('-');
                    prev_dash = true;
                }
            }
            Some(c) => {
                out.push(c);
                prev_dash = false;
            }
            None => {}
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "untitled".to_string()
    } else {
        out
    }
}

/// Tracks issued entry paths and disambiguates collisions by appending a
/// short uuid fragment (then a counter, if even that clashes).
#[derive(Default)]
pub struct PathAllocator {
    used: HashSet<String>,
}

impl PathAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a unique path, given the desired path and the item uuid used
    /// for disambiguation.
    pub fn allocate(&mut self, desired: &str, uuid: &str) -> String {
        if self.used.insert(desired.to_string()) {
            return desired.to_string();
        }
        let frag: String = uuid
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(6)
            .collect();
        let mut candidate = if frag.is_empty() {
            format!("{desired}-2")
        } else {
            format!("{desired}-{frag}")
        };
        let mut n = 2;
        while !self.used.insert(candidate.clone()) {
            n += 1;
            candidate = format!("{desired}-{frag}-{n}");
        }
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_slugify() {
        assert_eq!(slugify("My Login"), "my-login");
        assert_eq!(slugify("  GitHub / Work  "), "github-work");
        assert_eq!(slugify("AT&T Account"), "at-t-account");
        assert_eq!(slugify("note.one_two"), "note.one_two");
        assert_eq!(slugify(""), "untitled");
        assert_eq!(slugify("***"), "untitled");
    }

    #[test]
    fn allocator_disambiguates() {
        let mut a = PathAllocator::new();
        assert_eq!(a.allocate("logins/x", "abcdef123"), "logins/x");
        assert_eq!(a.allocate("logins/x", "abcdef123"), "logins/x-abcdef");
        assert_eq!(a.allocate("logins/x", "abcdef123"), "logins/x-abcdef-3");
    }
}
