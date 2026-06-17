//! Thin wrapper around the `pass` CLI plus store-path helpers.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// Resolve the password store directory: explicit override, else
/// `$PASSWORD_STORE_DIR`, else `~/.password-store`.
pub fn resolve_store_dir(override_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = override_dir {
        return d.to_path_buf();
    }
    if let Ok(d) = std::env::var("PASSWORD_STORE_DIR")
        && !d.is_empty()
    {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".password-store")
}

/// Does an entry already exist at this store path?
pub fn entry_exists(store_dir: &Path, entry_path: &str) -> bool {
    store_dir.join(format!("{entry_path}.gpg")).exists()
}

/// Insert a multiline entry via `pass insert -m [-f] <path>`, feeding `body`
/// on stdin. `store_dir` is passed through as `PASSWORD_STORE_DIR`.
pub fn insert(store_dir: &Path, entry_path: &str, body: &str, force: bool) -> Result<()> {
    let mut cmd = Command::new("pass");
    cmd.env("PASSWORD_STORE_DIR", store_dir)
        .arg("insert")
        .arg("-m");
    if force {
        cmd.arg("-f");
    }
    cmd.arg(entry_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to run `pass` — is it installed and on PATH?")?;
    child
        .stdin
        .take()
        .context("could not open pass stdin")?
        .write_all(body.as_bytes())
        .context("writing entry body to pass")?;

    let output = child.wait_with_output().context("waiting for pass")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("pass insert {entry_path} failed: {}", stderr.trim());
    }
    Ok(())
}
