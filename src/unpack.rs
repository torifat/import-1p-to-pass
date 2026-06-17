//! Open a `.1pux` archive: read `export.data` and extract `files/` payloads.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use zip::ZipArchive;

use crate::model::Export;

pub struct Archive {
    zip: ZipArchive<File>,
    /// All entry names inside the archive (used to locate `files/` payloads).
    names: Vec<String>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let zip = ZipArchive::new(file)
            .with_context(|| format!("{} is not a valid .1pux (zip) archive", path.display()))?;
        let names = (0..zip.len())
            .filter_map(|i| zip.name_for_index(i).map(|s| s.to_string()))
            .collect();
        Ok(Self { zip, names })
    }

    /// Parse the `export.data` JSON document.
    pub fn read_export(&mut self) -> Result<Export> {
        let mut entry = self
            .zip
            .by_name("export.data")
            .context("archive has no export.data (is this really a .1pux file?)")?;
        let mut buf = String::new();
        entry
            .read_to_string(&mut buf)
            .context("reading export.data")?;
        serde_json::from_str(&buf).context("parsing export.data JSON")
    }

    /// Return the bytes of the attachment with the given documentId, if present.
    /// 1Password stores payloads under `files/` with the documentId in the name.
    pub fn read_attachment(&mut self, document_id: &str) -> Result<Option<Vec<u8>>> {
        if document_id.is_empty() {
            return Ok(None);
        }
        let matched = self
            .names
            .iter()
            .find(|n| n.starts_with("files/") && n.contains(document_id))
            .cloned();
        let Some(name) = matched else {
            return Ok(None);
        };
        let mut entry = self
            .zip
            .by_name(&name)
            .map_err(|e| anyhow!("reading attachment {name}: {e}"))?;
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("reading {name}"))?;
        Ok(Some(buf))
    }
}
