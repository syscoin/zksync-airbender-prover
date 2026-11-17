//! Derive the app commitment for offline qualification before registering a new settlement key.
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use protocol_version::ProgramCommitment;
use sha2::{Digest, Sha256};
use verifier_common::SecurityModel;
use zkos_wrapper::circuits::BinaryCommitment;
use zksync_airbender_execution_utils::verifier_binaries::recursion_artifact;
use zksync_airbender_execution_utils::{RecursionArtifact, RecursionLayer};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    app_bin: PathBuf,
    #[arg(long)]
    app_text: PathBuf,
}

fn derive(args: Args) -> anyhow::Result<()> {
    let bin = std::fs::read(args.app_bin).context("reading guest binary")?;
    let text = std::fs::read(args.app_text).context("reading guest instruction section")?;
    let load = |layer, kind| recursion_artifact(SecurityModel::Security100, layer, kind);
    let commitment = BinaryCommitment::from_binaries(
        &bin,
        &text,
        load(RecursionLayer::Unrolled, RecursionArtifact::Bin),
        load(RecursionLayer::Unrolled, RecursionArtifact::Txt),
        load(RecursionLayer::Unified, RecursionArtifact::Bin),
        load(RecursionLayer::Unified, RecursionArtifact::Txt),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "security_bits": 100,
            "domain_log": zkos_wrapper::L1_VERIFIER_DOMAIN_SIZE_LOG,
            "app_bin_sha256": format!("{:x}", Sha256::digest(&bin)),
            "app_text_sha256": format!("{:x}", Sha256::digest(&text)),
            "unified_end_params": commitment.end_params,
            "program_commitment_words": commitment.aux_params,
            "program_commitment": ProgramCommitment(commitment.aux_params).to_string(),
        }))?
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::thread::Builder::new()
        .name("derive-syscoin-app-commitment".into())
        .stack_size(256 * 1024 * 1024)
        .spawn(move || derive(args))?
        .join()
        .map_err(|_| anyhow::anyhow!("app commitment derivation panicked"))?
}
