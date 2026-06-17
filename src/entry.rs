//! Build a pass entry (path + multiline body) from a 1Password item.

use crate::category;
use crate::fieldval::{self, Rendered};
use crate::model::{FieldValue, Item};
use crate::slug;

/// A file we need to pull out of the zip's `files/` dir for this entry.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub document_id: String,
    pub file_name: String,
}

/// Everything needed to place one entry into the store.
pub struct BuiltEntry {
    pub category_slug: String,
    pub title_slug: String,
    pub body: String,
    pub attachments: Vec<Attachment>,
}

pub struct BuildOpts {
    pub include_totp: bool,
    pub include_attachments: bool,
    pub include_password_history: bool,
}

/// Render an item into a `BuiltEntry`. The caller composes the final store
/// path (optionally prefixing the vault) and resolves collisions.
pub fn build(item: &Item, opts: &BuildOpts) -> BuiltEntry {
    let category_slug = category::slug(&item.category_uuid);
    let title_slug = slug::slugify(&item.overview.title);

    let (password, consumed) = primary_secret(item);

    let mut lines: Vec<String> = Vec::new();
    // Line 1 is always the password (possibly blank, which is valid for pass).
    lines.push(password);

    // Username (logins only have a designated one).
    if let Some(u) = login_field(item, "username")
        && !u.is_empty()
    {
        lines.push(format!("username: {u}"));
    }

    // Primary + additional URLs.
    if !item.overview.url.trim().is_empty() {
        lines.push(format!("url: {}", item.overview.url.trim()));
    }
    for u in &item.overview.urls {
        let url = u.url.trim();
        if !url.is_empty() && url != item.overview.url.trim() {
            lines.push(format!("url: {url}"));
        }
    }

    // Section fields -> metadata lines; TOTP and multi-line blocks deferred.
    let mut otpauth: Vec<String> = Vec::new();
    let mut blocks: Vec<(String, String)> = Vec::new();
    for (si, section) in item.details.sections.iter().enumerate() {
        for (fi, field) in section.fields.iter().enumerate() {
            if consumed == Some((si, fi)) {
                continue; // already used as the line-1 secret
            }
            for piece in fieldval::render(field) {
                match piece {
                    Rendered::Meta { key, value } => lines.push(format!("{key}: {value}")),
                    Rendered::Otp(v) => {
                        if opts.include_totp {
                            otpauth.push(to_otpauth(&v, &item.overview.title));
                        }
                    }
                    Rendered::Block { label, content } => blocks.push((label, content)),
                }
            }
        }
    }
    lines.extend(otpauth);

    // Tags.
    let tags: Vec<&str> = item
        .overview
        .tags
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    if !tags.is_empty() {
        lines.push(format!("tags: {}", tags.join(", ")));
    }

    // Attachments: collect refs and add a metadata line each.
    let mut attachments = Vec::new();
    if opts.include_attachments {
        attachments = collect_attachments(item);
        for a in &attachments {
            lines.push(format!("attachment: {}", a.file_name));
        }
    }

    // Multi-line blocks (e.g. SSH private keys) go after the metadata.
    for (label, content) in blocks {
        lines.push(String::new());
        lines.push(format!("{label}:"));
        lines.push(content.replace("\r\n", "\n").trim_end().to_string());
    }

    // Notes come next, verbatim (may be multi-line).
    let notes = item.details.notes_plain.trim_end();
    if !notes.is_empty() {
        lines.push(String::new());
        lines.push(notes.to_string());
    }

    // Password history is an opt-in archive, kept at the very bottom.
    if opts.include_password_history
        && let Some(block) = password_history_block(item)
    {
        lines.push(String::new());
        lines.push(block);
    }

    // pass expects a trailing newline.
    let mut body = lines.join("\n");
    body.push('\n');

    BuiltEntry {
        category_slug,
        title_slug,
        body,
        attachments,
    }
}

/// Returns the line-1 secret and, if it came from a section field, that
/// field's `(section_idx, field_idx)` so we don't also emit it as metadata.
fn primary_secret(item: &Item) -> (String, Option<(usize, usize)>) {
    if category::is_login(&item.category_uuid)
        && let Some(p) = login_field(item, "password")
    {
        return (p, None);
    }
    if category::is_password(&item.category_uuid)
        && let Some(p) = &item.details.password
        && !p.is_empty()
    {
        return (p.clone(), None);
    }
    // Credit cards: the card number is the natural "first line" secret.
    if item.category_uuid == "002" {
        for (si, section) in item.details.sections.iter().enumerate() {
            for (fi, field) in section.fields.iter().enumerate() {
                if let FieldValue::CreditCardNumber(n) = &field.value
                    && !n.trim().is_empty()
                {
                    return (n.clone(), Some((si, fi)));
                }
            }
        }
    }
    (String::new(), None)
}

fn login_field(item: &Item, designation: &str) -> Option<String> {
    item.details
        .login_fields
        .iter()
        .find(|f| f.designation == designation)
        .map(|f| f.value.clone())
}

fn collect_attachments(item: &Item) -> Vec<Attachment> {
    let mut out = Vec::new();
    if let Some(doc) = &item.details.document_attributes
        && !doc.document_id.is_empty()
    {
        out.push(Attachment {
            document_id: doc.document_id.clone(),
            file_name: nonblank_name(&doc.file_name),
        });
    }
    for section in &item.details.sections {
        for field in &section.fields {
            if let FieldValue::File(f) = &field.value
                && !f.document_id.is_empty()
            {
                out.push(Attachment {
                    document_id: f.document_id.clone(),
                    file_name: nonblank_name(&f.file_name),
                });
            }
        }
    }
    out
}

fn nonblank_name(name: &str) -> String {
    if name.trim().is_empty() {
        "attachment".to_string()
    } else {
        name.to_string()
    }
}

/// Convert a TOTP field into an `otpauth://` line. Pass through real URIs;
/// otherwise wrap a bare secret with the item title as issuer/label.
fn to_otpauth(value: &str, title: &str) -> String {
    let v = value.trim();
    if v.starts_with("otpauth://") {
        return v.to_string();
    }
    let label = percent_encode(title.trim());
    let secret = percent_encode(v);
    let issuer = percent_encode(title.trim());
    format!("otpauth://totp/{label}?secret={secret}&issuer={issuer}")
}

/// Build the `password history:` block, newest first, with ISO dates.
/// Returns `None` if the item has no usable history.
fn password_history_block(item: &Item) -> Option<String> {
    let mut entries: Vec<(i64, &str)> = item
        .details
        .password_history
        .iter()
        .filter(|e| !e.value.is_empty())
        .map(|e| (e.time.unwrap_or(0), e.value.as_str()))
        .collect();
    if entries.is_empty() {
        return None;
    }
    // Newest first; entries without a time (0) sort to the bottom.
    entries.sort_by_key(|&(time, _)| std::cmp::Reverse(time));

    let mut out = String::from("password history:");
    for (time, value) in entries {
        let date = if time > 0 {
            epoch_to_date(time)
        } else {
            "unknown".to_string()
        };
        out.push('\n');
        out.push_str(&format!("{date}: {value}"));
    }
    Some(out)
}

/// Convert a Unix timestamp (seconds) to `YYYY-MM-DD` (UTC).
/// Uses Howard Hinnant's civil-from-days algorithm — no date dependency.
fn epoch_to_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Minimal percent-encoding for otpauth label/query components.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Details, Field, LoginField, Overview, Section};

    fn login_item() -> Item {
        Item {
            uuid: "u1".into(),
            category_uuid: "001".into(),
            state: "active".into(),
            details: Details {
                login_fields: vec![
                    LoginField {
                        value: "alice".into(),
                        name: "username".into(),
                        designation: "username".into(),
                    },
                    LoginField {
                        value: "s3cret".into(),
                        name: "password".into(),
                        designation: "password".into(),
                    },
                ],
                notes_plain: "line one\nline two".into(),
                sections: vec![Section {
                    title: "Extra".into(),
                    fields: vec![Field {
                        title: "Recovery Key".into(),
                        id: "x".into(),
                        value: FieldValue::Concealed("abcd-efgh".into()),
                    }],
                }],
                ..Default::default()
            },
            overview: Overview {
                title: "GitHub".into(),
                url: "https://github.com".into(),
                tags: vec!["dev".into(), "work".into()],
                ..Default::default()
            },
        }
    }

    fn opts() -> BuildOpts {
        BuildOpts {
            include_totp: true,
            include_attachments: true,
            include_password_history: false,
        }
    }

    #[test]
    fn login_renders_password_first() {
        let e = build(&login_item(), &opts());
        let lines: Vec<&str> = e.body.lines().collect();
        assert_eq!(lines[0], "s3cret");
        assert!(lines.contains(&"username: alice"));
        assert!(lines.contains(&"url: https://github.com"));
        assert!(lines.contains(&"recovery-key: abcd-efgh"));
        assert!(lines.contains(&"tags: dev, work"));
        assert_eq!(e.category_slug, "logins");
        assert_eq!(e.title_slug, "github");
        // Notes appear after a blank separator at the end.
        assert!(e.body.ends_with("line one\nline two\n"));
    }

    #[test]
    fn totp_becomes_otpauth_line() {
        let mut item = login_item();
        item.details.sections.push(Section {
            title: "".into(),
            fields: vec![Field {
                title: "one-time password".into(),
                id: "t".into(),
                value: FieldValue::Totp("JBSWY3DPEHPK3PXP".into()),
            }],
        });
        let e = build(&item, &opts());
        assert!(
            e.body
                .lines()
                .any(|l| l.starts_with("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"))
        );
    }

    #[test]
    fn credit_card_number_is_first_line() {
        let item = Item {
            uuid: "c1".into(),
            category_uuid: "002".into(),
            state: "active".into(),
            details: Details {
                sections: vec![Section {
                    title: "".into(),
                    fields: vec![Field {
                        title: "number".into(),
                        id: "ccnum".into(),
                        value: FieldValue::CreditCardNumber("4111111111111111".into()),
                    }],
                }],
                ..Default::default()
            },
            overview: Overview {
                title: "Visa".into(),
                ..Default::default()
            },
        };
        let e = build(&item, &opts());
        assert_eq!(e.body.lines().next().unwrap(), "4111111111111111");
        assert_eq!(e.category_slug, "credit-cards");
        // The number must not be duplicated as a metadata line.
        assert_eq!(e.body.matches("4111111111111111").count(), 1);
    }

    #[test]
    fn secure_note_has_blank_first_line() {
        let item = Item {
            uuid: "n1".into(),
            category_uuid: "003".into(),
            state: "active".into(),
            details: Details {
                notes_plain: "remember this".into(),
                ..Default::default()
            },
            overview: Overview {
                title: "Note One".into(),
                ..Default::default()
            },
        };
        let e = build(&item, &opts());
        assert_eq!(e.body.lines().next().unwrap(), "");
        assert_eq!(e.category_slug, "secure-notes");
        assert_eq!(e.title_slug, "note-one");
    }

    #[test]
    fn password_history_is_opt_in_and_newest_first() {
        use crate::model::PasswordHistoryEntry;
        let mut item = login_item();
        item.details.password_history = vec![
            PasswordHistoryEntry {
                value: "older".into(),
                time: Some(1_500_000_000),
            },
            PasswordHistoryEntry {
                value: "newer".into(),
                time: Some(1_600_000_000),
            },
            PasswordHistoryEntry {
                value: "".into(),
                time: Some(1_700_000_000),
            }, // dropped
        ];

        // Off by default.
        assert!(!build(&item, &opts()).body.contains("password history:"));

        // On when requested: newest first, ISO dates, empty values skipped.
        let on = BuildOpts {
            include_totp: true,
            include_attachments: true,
            include_password_history: true,
        };
        let body = build(&item, &on).body;
        let hist: Vec<&str> = body
            .lines()
            .skip_while(|l| *l != "password history:")
            .collect();
        assert_eq!(hist[0], "password history:");
        assert_eq!(hist[1], "2020-09-13: newer");
        assert_eq!(hist[2], "2017-07-14: older");
        assert_eq!(hist.len(), 3); // header + 2 entries, blank value dropped
    }
}
