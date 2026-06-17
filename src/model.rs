//! Serde structs mirroring the subset of `export.data` we care about.
//!
//! 1Password adds fields over time, so every struct is permissive: unknown
//! fields are ignored and missing fields fall back to `Default`.
//!
//! Some fields are decoded but not yet consumed by the importer; they are kept
//! to document the format and are exempt from dead-code warnings.
#![allow(dead_code)]

use serde::Deserialize;

/// Top-level `export.data` document.
#[derive(Debug, Deserialize, Default)]
pub struct Export {
    #[serde(default)]
    pub accounts: Vec<Account>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Account {
    #[serde(default)]
    pub attrs: AccountAttrs,
    #[serde(default)]
    pub vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AccountAttrs {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Vault {
    #[serde(default)]
    pub attrs: VaultAttrs,
    /// Kept as raw JSON so a single malformed item can be skipped with a
    /// warning rather than aborting the whole import. Deserialised per-item
    /// into [`Item`] by the caller.
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct VaultAttrs {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Item {
    #[serde(default)]
    pub uuid: String,
    #[serde(rename = "categoryUuid", default)]
    pub category_uuid: String,
    /// "active" or "archived"; missing is treated as active.
    #[serde(default = "default_state")]
    pub state: String,
    #[serde(default)]
    pub details: Details,
    #[serde(default)]
    pub overview: Overview,
}

fn default_state() -> String {
    "active".to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct Details {
    #[serde(rename = "loginFields", default)]
    pub login_fields: Vec<LoginField>,
    #[serde(rename = "notesPlain", default)]
    pub notes_plain: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(rename = "passwordHistory", default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(rename = "documentAttributes", default)]
    pub document_attributes: Option<DocumentAttributes>,
}

/// One previously-used password: the value plus when it stopped being current.
#[derive(Debug, Deserialize, Default)]
pub struct PasswordHistoryEntry {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub time: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
pub struct LoginField {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub name: String,
    /// "username" or "password" for the primary fields.
    #[serde(default)]
    pub designation: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Section {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Field {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub value: FieldValue,
}

/// Tagged union of section-field value types. 1Password serialises this as a
/// single-key object, e.g. `{"concealed": "..."}` or `{"address": {...}}`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum FieldValue {
    String(String),
    Concealed(String),
    Email(EmailValue),
    Url(String),
    Totp(String),
    Phone(String),
    Date(Option<i64>),
    MonthYear(Option<i64>),
    Gender(String),
    Menu(String),
    Address(Address),
    CreditCardType(String),
    CreditCardNumber(String),
    Reference(String),
    File(FileRef),
    SshKey(SshKey),
    SsoLogin(SsoLogin),
    /// Any value shape we don't model yet (keeps deserialisation total).
    #[serde(other)]
    #[default]
    Unknown,
}

/// `sshKey` field: the private key plus public/fingerprint/type metadata.
#[derive(Debug, Deserialize, Default)]
pub struct SshKey {
    #[serde(rename = "privateKey", default)]
    pub private_key: String,
    #[serde(default)]
    pub metadata: SshKeyMetadata,
}

#[derive(Debug, Deserialize, Default)]
pub struct SshKeyMetadata {
    #[serde(rename = "publicKey", default)]
    pub public_key: String,
    #[serde(default)]
    pub fingerprint: String,
    /// Sometimes a string (`"ed25519"`), sometimes an object (`{"rsa":"Rsa2048"}`).
    #[serde(rename = "keyType", default)]
    pub key_type: serde_json::Value,
}

/// `ssoLogin` field: which SSO provider backs this item.
#[derive(Debug, Deserialize, Default)]
pub struct SsoLogin {
    #[serde(default)]
    pub provider: String,
}

/// Email fields are sometimes a bare string, sometimes `{email_address, provider}`.
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
pub enum EmailValue {
    Plain(String),
    Structured {
        #[serde(default)]
        email_address: String,
    },
    #[default]
    None,
}

#[derive(Debug, Deserialize, Default)]
pub struct Address {
    #[serde(default)]
    pub street: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub zip: String,
    #[serde(default)]
    pub country: String,
}

/// A `file`-typed section field references an entry in the zip's `files/` dir.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct FileRef {
    #[serde(rename = "fileName", default)]
    pub file_name: String,
    #[serde(rename = "documentId", default)]
    pub document_id: String,
}

/// Document-category items attach their payload via `documentAttributes`.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct DocumentAttributes {
    #[serde(rename = "fileName", default)]
    pub file_name: String,
    #[serde(rename = "documentId", default)]
    pub document_id: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Overview {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub urls: Vec<UrlEntry>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UrlEntry {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub url: String,
}
