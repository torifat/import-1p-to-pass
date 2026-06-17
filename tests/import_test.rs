//! End-to-end test: build a synthetic .1pux, set up a throwaway GPG key and
//! pass store, run the binary, and assert the entries round-trip.
//!
//! Requires `pass` and `gpg` on PATH; if either is missing the test no-ops.

use std::io::Write;
use std::path::Path;
use std::process::Command;

const SAMPLE_JSON: &str = r#"{
  "accounts": [{
    "attrs": { "name": "Personal Account" },
    "vaults": [{
      "attrs": { "name": "Personal" },
      "items": [
        {
          "uuid": "LOGIN0001",
          "categoryUuid": "001",
          "state": "active",
          "details": {
            "loginFields": [
              {"value": "alice", "name": "username", "designation": "username"},
              {"value": "hunter2", "name": "password", "designation": "password"}
            ],
            "notesPlain": "be careful",
            "sections": [
              {"title": "", "fields": [
                {"title": "one-time password", "id": "otp", "value": {"totp": "JBSWY3DPEHPK3PXP"}},
                {"title": "expiry", "id": "exp", "value": {"monthYear": null}}
              ]}
            ]
          },
          "overview": { "title": "Example Login", "url": "https://example.com", "tags": ["personal"] }
        },
        {
          "uuid": "NOTE0001",
          "categoryUuid": "003",
          "state": "active",
          "details": { "notesPlain": "top secret note" },
          "overview": { "title": "My Note" }
        },
        {
          "uuid": "DOC0001",
          "categoryUuid": "006",
          "state": "active",
          "details": { "documentAttributes": { "fileName": "secret.txt", "documentId": "DOC123" } },
          "overview": { "title": "My Document" }
        },
        {
          "uuid": "ARCH0001",
          "categoryUuid": "001",
          "state": "archived",
          "details": {},
          "overview": { "title": "Old Archived" }
        }
      ]
    }]
  }]
}"#;

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Write the synthetic .1pux (export.data + one attachment) to `path`.
fn write_sample_1pux(path: &Path) {
    use zip::write::SimpleFileOptions;
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("export.data", opts).unwrap();
    zip.write_all(SAMPLE_JSON.as_bytes()).unwrap();
    // Attachment payload; name embeds the documentId referenced above.
    zip.start_file("files/DOC123__secret.txt", opts).unwrap();
    zip.write_all(b"the secret document body").unwrap();
    zip.finish().unwrap();
}

/// Generate a passphraseless ed25519 key in `gnupg_home`, return its email id.
fn gen_gpg_key(gnupg_home: &Path) -> String {
    let email = "test-import@example.com";
    let params = format!(
        "%no-protection\n\
         Key-Type: eddsa\nKey-Curve: ed25519\n\
         Subkey-Type: ecdh\nSubkey-Curve: cv25519\n\
         Name-Real: Test Import\nName-Email: {email}\n\
         Expire-Date: 0\n%commit\n"
    );
    let status = Command::new("gpg")
        .env("GNUPGHOME", gnupg_home)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--gen-key",
            "/dev/stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(params.as_bytes())?;
            c.wait()
        })
        .expect("spawning gpg --gen-key");
    assert!(status.success(), "gpg key generation failed");
    email.to_string()
}

fn pass_show(store: &Path, gnupg: &Path, entry: &str) -> String {
    let out = Command::new("pass")
        .env("PASSWORD_STORE_DIR", store)
        .env("GNUPGHOME", gnupg)
        .arg("show")
        .arg(entry)
        .output()
        .expect("running pass show");
    assert!(
        out.status.success(),
        "pass show {entry} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn imports_sample_1pux_into_pass() {
    if !have("pass") || !have("gpg") {
        eprintln!("skipping: pass and/or gpg not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let gnupg = tmp.path().join("gnupg");
    let store = tmp.path().join("store");
    let pux = tmp.path().join("sample.1pux");
    std::fs::create_dir_all(&gnupg).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gnupg, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    write_sample_1pux(&pux);
    let key_id = gen_gpg_key(&gnupg);

    // Initialise the store.
    let init = Command::new("pass")
        .env("PASSWORD_STORE_DIR", &store)
        .env("GNUPGHOME", &gnupg)
        .arg("init")
        .arg(&key_id)
        .output()
        .expect("running pass init");
    assert!(
        init.status.success(),
        "pass init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Run the importer.
    let bin = env!("CARGO_BIN_EXE_import-1p-to-pass");
    let run = Command::new(bin)
        .env("GNUPGHOME", &gnupg)
        .arg("--store-dir")
        .arg(&store)
        .arg(&pux)
        .output()
        .expect("running importer");
    assert!(
        run.status.success(),
        "importer failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Login round-trips with password on line 1 + metadata + otpauth.
    let login = pass_show(&store, &gnupg, "logins/example-login");
    let lines: Vec<&str> = login.lines().collect();
    assert_eq!(lines[0], "hunter2");
    assert!(
        login.contains("username: alice"),
        "missing username:\n{login}"
    );
    assert!(login.contains("url: https://example.com"));
    assert!(
        login.contains("otpauth://totp/Example%20Login?secret=JBSWY3DPEHPK3PXP"),
        "missing otpauth:\n{login}"
    );
    assert!(login.contains("be careful"));

    // Secure note.
    let note = pass_show(&store, &gnupg, "secure-notes/my-note");
    assert!(note.contains("top secret note"));

    // Document entry + extracted, re-encrypted attachment.
    assert!(store.join("documents/my-document.gpg").exists());
    let att = store.join("documents/my-document.attachments/secret.txt.gpg");
    assert!(att.exists(), "attachment not written");
    let att_plain = Command::new("gpg")
        .env("GNUPGHOME", &gnupg)
        .args(["--batch", "--quiet", "--decrypt"])
        .arg(&att)
        .output()
        .expect("decrypting attachment");
    assert!(att_plain.status.success());
    assert_eq!(
        String::from_utf8_lossy(&att_plain.stdout),
        "the secret document body"
    );

    // Archived item was skipped.
    assert!(
        !store.join("logins/old-archived.gpg").exists(),
        "archived item should be skipped"
    );
}
