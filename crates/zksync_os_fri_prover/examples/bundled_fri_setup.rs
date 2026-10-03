//! Explicit CPU-only release generation or exact comparison of all three summaries.
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context;
use clap::Parser;
use sha2::{Digest, Sha256};
use zksync_os_fri_prover::setup_summaries::{
    derive_release_artifact, verify_derived_release_artifact,
};

#[derive(Parser)]
#[command(
    about = "Explicitly rederive all three canonical FRI setup summaries on CPU; no GPU or proving"
)]
struct Args {
    #[arg(long)]
    app_bin_path: Option<PathBuf>,
    #[arg(long)]
    app_text_path: Option<PathBuf>,
    /// Write to a new file only. Never overwrites an existing release artifact.
    #[arg(long, required_unless_present = "verify", conflicts_with = "verify")]
    output: Option<PathBuf>,
    /// Derive from scratch and compare every metadata field and cap word with the bundle.
    #[arg(long)]
    verify: bool,
}

fn execute(args: Args) -> anyhow::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bin = args
        .app_bin_path
        .unwrap_or_else(|| root.join("multiblock_batch.bin"));
    let text = args
        .app_text_path
        .unwrap_or_else(|| bin.with_extension("text"));
    // Reserve the output before the expensive derivation. A failed run leaves a
    // visibly incomplete file; it is never a usable runtime cache.
    let mut output = args
        .output
        .as_ref()
        .map(|path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("create new artifact {}", path.display()))
        })
        .transpose()?;
    let started = Instant::now();
    let artifact = derive_release_artifact(&bin, &text)?;
    if args.verify {
        verify_derived_release_artifact(&bin, &text, &artifact)?;
    }
    if let Some(file) = output.as_mut() {
        file.write_all(&artifact)?;
        file.sync_all()?;
    }
    println!(
        "{}",
        serde_json::json!({
            "derived_all_three_setups": true,
            "matches_complete_bundled_artifact": if args.verify { Some(true) } else { None },
            "artifact_sha256": format!("{:x}", Sha256::digest(&artifact)),
            "artifact_bytes": artifact.len(),
            "elapsed_seconds": started.elapsed().as_secs_f64(),
            "output": args.output,
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::thread::Builder::new()
        .name("derive-bundled-fri-setups".to_owned())
        .stack_size(256 * 1024 * 1024)
        .spawn(move || execute(args))?
        .join()
        .map_err(|_| anyhow::anyhow!("FRI setup derivation panicked"))?
}
