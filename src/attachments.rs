//! Extract `.1pux` attachments and GPG-encrypt them into the store.
//!
//! pass itself only manages `.gpg` files, so attachments are written next to
//! their entry under `<entry>.attachments/<filename>.gpg`, encrypted to the
//! same recipients listed in the store's top-level `.gpg-id`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::slug;

/// Read recipient ids from `<store>/.gpg-id` (one per line).
pub fn read_gpg_ids(store_dir: &Path) -> Result<Vec<String>> {
    let path = store_dir.join(".gpg-id");
    let content = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} — is the store initialised with `pass init`?",
            path.display()
        )
    })?;
    let ids: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if ids.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(ids)
}

/// Encrypt `bytes` to `recipients` and write to
/// `<store>/<entry_path>.attachments/<safe_file_name>.gpg`.
/// Returns the path written.
pub fn write_attachment(
    store_dir: &Path,
    entry_path: &str,
    file_name: &str,
    bytes: &[u8],
    recipients: &[String],
) -> Result<PathBuf> {
    let dir = store_dir.join(format!("{entry_path}.attachments"));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let out = dir.join(format!("{}.gpg", safe_file_name(file_name)));

    let mut cmd = Command::new("gpg");
    cmd.arg("--batch").arg("--yes").arg("--encrypt");
    for r in recipients {
        cmd.arg("--recipient").arg(r);
    }
    cmd.arg("--output").arg(&out);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to run `gpg` for attachment encryption")?;
    child
        .stdin
        .take()
        .context("could not open gpg stdin")?
        .write_all(bytes)
        .context("writing attachment bytes to gpg")?;
    let output = child.wait_with_output().context("waiting for gpg")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gpg encrypt of {file_name} failed: {}", stderr.trim());
    }
    Ok(out)
}

/// Keep the extension readable while slugifying the stem, so
/// "My Doc.pdf" -> "my-doc.pdf".
fn safe_file_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !ext.is_empty() && !ext.contains('/') => {
            format!("{}.{}", slug::slugify(stem), slug::slugify(ext))
        }
        _ => slug::slugify(name),
    }
}
