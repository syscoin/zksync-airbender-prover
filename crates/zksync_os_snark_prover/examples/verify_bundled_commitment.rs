//! Explicit, slow release-artifact verification; never part of normal startup.
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context as _;
use clap::Parser;
use zkos_wrapper::circuits::BinaryCommitment;
use zksync_os_snark_prover::binary_commitment::{
    load_bundled_commitment, verify_derived_commitment,
};

#[derive(Parser)]
#[command(about = "Recompute and verify the complete bundled Syscoin binary commitment")]
struct Args {
    #[arg(long)]
    app_bin_path: Option<PathBuf>,
    #[arg(long)]
    app_text_path: Option<PathBuf>,
}

fn verify(args: Args) -> anyhow::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bin = args
        .app_bin_path
        .unwrap_or_else(|| root.join("multiblock_batch.bin"));
    let text = args
        .app_text_path
        .unwrap_or_else(|| bin.with_extension("text"));
    // Refuse incorrect inputs before the expensive derivation.
    load_bundled_commitment(&bin, &text)?;
    let binary = std::fs::read(&bin).with_context(|| format!("read {bin:?}"))?;
    let text_bytes = std::fs::read(&text).with_context(|| format!("read {text:?}"))?;
    let started = Instant::now();
    let derived = BinaryCommitment::from_base_binary(&binary, &text_bytes);
    verify_derived_commitment(&bin, &text, &derived)?;
    println!(
        "{}",
        serde_json::json!({
            "matches_bundled_commitment": true,
            "end_params": derived.end_params,
            "aux_params": derived.aux_params,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::thread::Builder::new()
        .name("verify-bundled-commitment".to_owned())
        .stack_size(256 * 1024 * 1024)
        .spawn(move || verify(args))?
        .join()
        .map_err(|_| anyhow::anyhow!("commitment derivation panicked"))?
}
