//! Render a section field into zero or more output pieces.

use crate::model::{Address, EmailValue, Field, FieldValue, SshKey};
use crate::slug;

/// One rendered piece of a field. A single field can yield several (e.g. an
/// SSH key produces public-key/fingerprint metadata plus a private-key block).
pub enum Rendered {
    /// A `key: value` metadata line.
    Meta { key: String, value: String },
    /// A TOTP secret/URI; the caller turns it into an `otpauth://` line.
    Otp(String),
    /// Multi-line content appended at the end of the entry (e.g. a PEM key).
    Block { label: String, content: String },
}

/// Render a single field into zero or more pieces. Empty values are dropped so
/// we don't emit noise like `expiry_date: ` for unset fields.
pub fn render(field: &Field) -> Vec<Rendered> {
    let key = field_key(field);
    match &field.value {
        FieldValue::String(s)
        | FieldValue::Concealed(s)
        | FieldValue::Url(s)
        | FieldValue::Phone(s)
        | FieldValue::Gender(s)
        | FieldValue::Menu(s)
        | FieldValue::Reference(s)
        | FieldValue::CreditCardType(s)
        | FieldValue::CreditCardNumber(s) => meta(key, s.clone()),

        FieldValue::Totp(s) => {
            if s.trim().is_empty() {
                vec![]
            } else {
                vec![Rendered::Otp(s.clone())]
            }
        }

        FieldValue::Email(e) => meta(key, email_string(e)),

        FieldValue::Date(ts) => match ts {
            Some(t) if *t != 0 => meta(key, t.to_string()),
            _ => vec![],
        },
        FieldValue::MonthYear(my) => match my {
            Some(m) if *m != 0 => meta(key, format_month_year(*m)),
            _ => vec![],
        },

        FieldValue::Address(a) => meta(key, address_string(a)),

        FieldValue::SshKey(k) => render_ssh_key(key, k),

        FieldValue::SsoLogin(s) => meta("sso".to_string(), s.provider.clone()),

        // Files become attachments; nothing inline.
        FieldValue::File(_) | FieldValue::Unknown => vec![],
    }
}

fn meta(key: String, value: String) -> Vec<Rendered> {
    if value.trim().is_empty() {
        vec![]
    } else {
        vec![Rendered::Meta { key, value }]
    }
}

fn render_ssh_key(_key: String, k: &SshKey) -> Vec<Rendered> {
    let mut out = Vec::new();
    if !k.metadata.public_key.trim().is_empty() {
        out.push(Rendered::Meta {
            key: "public-key".into(),
            value: k.metadata.public_key.clone(),
        });
    }
    if !k.metadata.fingerprint.trim().is_empty() {
        out.push(Rendered::Meta {
            key: "fingerprint".into(),
            value: k.metadata.fingerprint.clone(),
        });
    }
    let key_type = key_type_string(&k.metadata.key_type);
    if !key_type.is_empty() {
        out.push(Rendered::Meta {
            key: "key-type".into(),
            value: key_type,
        });
    }
    if !k.private_key.trim().is_empty() {
        out.push(Rendered::Block {
            label: "private key".into(),
            content: k.private_key.clone(),
        });
    }
    out
}

/// Pick a stable, readable key for a field: prefer its title, fall back to id.
fn field_key(field: &Field) -> String {
    let base = if !field.title.trim().is_empty() {
        &field.title
    } else {
        &field.id
    };
    let s = slug::slugify(base);
    if s == "untitled" {
        "field".to_string()
    } else {
        s
    }
}

fn email_string(e: &EmailValue) -> String {
    match e {
        EmailValue::Plain(s) => s.clone(),
        EmailValue::Structured { email_address } => email_address.clone(),
        EmailValue::None => String::new(),
    }
}

fn address_string(a: &Address) -> String {
    [&a.street, &a.city, &a.state, &a.zip, &a.country]
        .into_iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `keyType` is either `"ed25519"` or `{"rsa":"Rsa2048"}`; reduce to a label.
fn key_type_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => map
            .values()
            .find_map(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| map.keys().next().cloned())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// `202110` -> `"2021-10"`.
fn format_month_year(my: i64) -> String {
    let year = my / 100;
    let month = my % 100;
    if (1..=12).contains(&month) {
        format!("{year:04}-{month:02}")
    } else {
        my.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Field;

    fn field(title: &str, value: FieldValue) -> Field {
        Field {
            title: title.to_string(),
            id: String::new(),
            value,
        }
    }

    fn first_meta(r: &[Rendered]) -> (&str, &str) {
        match &r[0] {
            Rendered::Meta { key, value } => (key, value),
            _ => panic!("expected meta"),
        }
    }

    #[test]
    fn renders_string_and_concealed() {
        let r = render(&field("API Key", FieldValue::Concealed("sk-123".into())));
        assert_eq!(first_meta(&r), ("api-key", "sk-123"));
    }

    #[test]
    fn totp_becomes_otp_piece() {
        let r = render(&field("one-time", FieldValue::Totp("otpauth://x".into())));
        assert!(matches!(r[0], Rendered::Otp(_)));
    }

    #[test]
    fn empty_values_skipped() {
        assert!(render(&field("blank", FieldValue::String("".into()))).is_empty());
        assert!(render(&field("zero", FieldValue::Date(Some(0)))).is_empty());
        assert!(render(&field("nuldate", FieldValue::Date(None))).is_empty());
        assert!(render(&field("doc", FieldValue::Unknown)).is_empty());
    }

    #[test]
    fn month_year_formatted() {
        let r = render(&field("Expiry", FieldValue::MonthYear(Some(202110))));
        assert_eq!(first_meta(&r).1, "2021-10");
    }

    #[test]
    fn address_flattened() {
        let a = Address {
            street: "1 Main".into(),
            city: "Anytown".into(),
            state: "CA".into(),
            zip: "90000".into(),
            country: "".into(),
        };
        let r = render(&field("Address", FieldValue::Address(a)));
        assert_eq!(first_meta(&r).1, "1 Main, Anytown, CA, 90000");
    }

    #[test]
    fn ssh_key_splits_into_meta_and_block() {
        use crate::model::{SshKey, SshKeyMetadata};
        let k = SshKey {
            private_key: "-----BEGIN-----\nabc\n-----END-----\n".into(),
            metadata: SshKeyMetadata {
                public_key: "ssh-ed25519 AAAA".into(),
                fingerprint: "SHA256:xyz".into(),
                key_type: "ed25519".into(),
            },
        };
        let r = render(&field("private key", FieldValue::SshKey(k)));
        assert_eq!(first_meta(&r), ("public-key", "ssh-ed25519 AAAA"));
        assert!(matches!(r.last().unwrap(), Rendered::Block { .. }));
    }
}
