//! import-1p-to-pass — import a 1Password `.1pux` export into pass.

mod attachments;
mod category;
mod entry;
mod fieldval;
mod model;
mod passcli;
mod progress;
mod slug;
mod unpack;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use entry::BuildOpts;
use slug::PathAllocator;

/// Import a 1Password Unencrypted Export (.1pux) into pass (passwordstore.org).
#[derive(Parser, Debug)]
#[command(name = "import-1p-to-pass", version, about)]
struct Cli {
    /// Path to the .1pux export file.
    export: PathBuf,

    /// Render entries to stdout without writing to the store.
    #[arg(long)]
    dry_run: bool,

    /// Overwrite entries that already exist.
    #[arg(long)]
    force: bool,

    /// Use this directory as PASSWORD_STORE_DIR for the run.
    #[arg(long, value_name = "PATH")]
    store_dir: Option<PathBuf>,

    /// Nest entries under the vault name (<vault>/<category>/<title>).
    #[arg(long)]
    vault_prefix: bool,

    /// Also import items whose state is not "active" (e.g. archived).
    #[arg(long)]
    include_archived: bool,

    /// Do not emit otpauth:// lines for TOTP fields.
    #[arg(long)]
    no_totp: bool,

    /// Do not extract file attachments.
    #[arg(long)]
    no_attachments: bool,

    /// Append previously-used passwords as a `password history:` block.
    #[arg(long)]
    password_history: bool,
}

#[derive(Default)]
struct Summary {
    imported: usize,
    skipped_archived: usize,
    skipped_existing: usize,
    renamed: usize,
    attachments: usize,
    errors: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let store_dir = passcli::resolve_store_dir(cli.store_dir.as_deref());
    let build_opts = BuildOpts {
        include_totp: !cli.no_totp,
        include_attachments: !cli.no_attachments,
        include_password_history: cli.password_history,
    };

    let mut archive = unpack::Archive::open(&cli.export)?;
    let export = archive.read_export()?;

    let mut allocator = PathAllocator::new();
    let mut summary = Summary::default();
    let mut gpg_ids: Option<Vec<String>> = None;

    let total = count_candidates(&export, cli.include_archived);
    let mut progress = progress::Progress::new(total, !cli.dry_run);

    for account in &export.accounts {
        for vault in &account.vaults {
            for raw in &vault.items {
                let item: model::Item = match serde_json::from_value(raw.clone()) {
                    Ok(i) => i,
                    Err(e) => {
                        progress.note(&format!("warning: skipping unparseable item: {e}"));
                        summary.errors += 1;
                        continue;
                    }
                };
                let item = &item;

                let archived = item.state != "active";
                if archived && !cli.include_archived {
                    summary.skipped_archived += 1;
                    continue;
                }

                let built = entry::build(item, &build_opts);
                let desired = compose_path(&built, &vault.attrs.name, cli.vault_prefix, archived);
                let path = allocator.allocate(&desired, &item.uuid);
                if path != desired {
                    summary.renamed += 1;
                }

                if cli.dry_run {
                    print_dry_run(&path, &built);
                    summary.imported += 1;
                    continue;
                }

                progress.tick(&path);

                if !cli.force && passcli::entry_exists(&store_dir, &path) {
                    progress.note(&format!("skip (exists): {path}"));
                    summary.skipped_existing += 1;
                    continue;
                }

                if let Err(e) = passcli::insert(&store_dir, &path, &built.body, cli.force) {
                    progress.note(&format!("error: {path}: {e:#}"));
                    summary.errors += 1;
                    continue;
                }
                summary.imported += 1;

                if !built.attachments.is_empty()
                    && let Err(e) = write_attachments(
                        &mut archive,
                        &store_dir,
                        &path,
                        &built.attachments,
                        &mut gpg_ids,
                        &mut summary,
                        &mut progress,
                    )
                {
                    progress.note(&format!("warning: {path}: attachments: {e:#}"));
                }
            }
        }
    }

    progress.finish();
    print_summary(&summary, cli.dry_run);
    if summary.errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Count items that will be attempted (active, or any when archived included).
/// Missing `state` is treated as active, matching [`model::Item`]'s default.
fn count_candidates(export: &model::Export, include_archived: bool) -> usize {
    export
        .accounts
        .iter()
        .flat_map(|a| &a.vaults)
        .flat_map(|v| &v.items)
        .filter(|raw| {
            let active = raw
                .get("state")
                .and_then(|s| s.as_str())
                .map(|s| s == "active")
                .unwrap_or(true);
            active || include_archived
        })
        .count()
}

/// Compose the final store path: `[archived/][<vault>/]<category>/<title>`.
fn compose_path(
    built: &entry::BuiltEntry,
    vault_name: &str,
    vault_prefix: bool,
    archived: bool,
) -> String {
    let mut segments: Vec<String> = Vec::new();
    if archived {
        segments.push("archived".to_string());
    }
    if vault_prefix {
        segments.push(slug::slugify(vault_name));
    }
    segments.push(built.category_slug.clone());
    segments.push(built.title_slug.clone());
    segments.join("/")
}

fn write_attachments(
    archive: &mut unpack::Archive,
    store_dir: &std::path::Path,
    entry_path: &str,
    items: &[entry::Attachment],
    gpg_ids: &mut Option<Vec<String>>,
    summary: &mut Summary,
    progress: &mut progress::Progress,
) -> Result<()> {
    if gpg_ids.is_none() {
        *gpg_ids = Some(attachments::read_gpg_ids(store_dir)?);
    }
    let recipients = gpg_ids.as_ref().unwrap();
    for a in items {
        let bytes = archive
            .read_attachment(&a.document_id)
            .with_context(|| format!("reading attachment {}", a.file_name))?;
        let Some(bytes) = bytes else {
            progress.note(&format!(
                "warning: {entry_path}: attachment {} not found in archive",
                a.file_name
            ));
            continue;
        };
        attachments::write_attachment(store_dir, entry_path, &a.file_name, &bytes, recipients)?;
        summary.attachments += 1;
    }
    Ok(())
}

fn print_dry_run(path: &str, built: &entry::BuiltEntry) {
    println!("=== {path} ===");
    for line in built.body.lines() {
        println!("  {line}");
    }
    for a in &built.attachments {
        println!("  [attachment] {}", a.file_name);
    }
    println!();
}

fn print_summary(s: &Summary, dry_run: bool) {
    let verb = if dry_run { "would import" } else { "imported" };
    eprintln!("\n{verb}: {}", s.imported);
    if s.skipped_archived > 0 {
        eprintln!("skipped (archived): {}", s.skipped_archived);
    }
    if s.skipped_existing > 0 {
        eprintln!("skipped (exists): {}", s.skipped_existing);
    }
    if s.renamed > 0 {
        eprintln!("renamed (collisions): {}", s.renamed);
    }
    if s.attachments > 0 {
        eprintln!("attachments written: {}", s.attachments);
    }
    if s.errors > 0 {
        eprintln!("errors: {}", s.errors);
    }
}
