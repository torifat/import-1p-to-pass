//! Map a 1Password `categoryUuid` to the top-level folder used in the store.

/// Returns the folder slug for a category uuid, e.g. `"001"` -> `"logins"`.
/// Unknown categories fall back to `category-<uuid>` so nothing is dropped.
pub fn slug(category_uuid: &str) -> String {
    let known = match category_uuid {
        "001" => "logins",
        "002" => "credit-cards",
        "003" => "secure-notes",
        "004" => "identities",
        "005" => "passwords",
        "006" => "documents",
        "100" => "software-licenses",
        "101" => "bank-accounts",
        "102" => "databases",
        "103" => "driver-licenses",
        "104" => "outdoor-licenses",
        "105" => "memberships",
        "106" => "passports",
        "107" => "reward-programs",
        "108" => "social-security-numbers",
        "109" => "wireless-routers",
        "110" => "servers",
        "111" => "email-accounts",
        "112" => "api-credentials",
        "113" => "medical-records",
        "114" => "ssh-keys",
        _ => return format!("category-{category_uuid}"),
    };
    known.to_string()
}

/// True for categories whose primary secret is a Login-style password field.
pub fn is_login(category_uuid: &str) -> bool {
    category_uuid == "001"
}

/// True for the standalone Password category (secret lives in `details.password`).
pub fn is_password(category_uuid: &str) -> bool {
    category_uuid == "005"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_categories() {
        assert_eq!(slug("001"), "logins");
        assert_eq!(slug("003"), "secure-notes");
        assert_eq!(slug("113"), "medical-records");
    }

    #[test]
    fn unknown_category_falls_back() {
        assert_eq!(slug("999"), "category-999");
        assert_eq!(slug(""), "category-");
    }
}
