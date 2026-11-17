//! V2 registers the app once on the GPU and embeds the two fixed recursion setups.
//! Authenticate the same guest bytes that the prover will execute.

use anyhow::{ensure, Context};
use clap::ValueEnum;
use sha2::{Digest, Sha256};
use zksync_airbender_cli::prover_utils::{ProgramSource, SecurityLevel};
use zksync_airbender_execution_utils::verifier_binaries::{
    derive_recursion_setup, recursion_setup,
};
use zksync_airbender_execution_utils::RecursionLayer;

const APP_BIN_SHA256: &str = "0d69bb7bc5207041c737def52d8858bab261b2ccf0afadbf2ceed14aa86d7cf6";
const APP_TEXT_SHA256: &str = "9d999d91bc7422488c58cf6ca1f7f5041c2972065592ffe98bfcb8220ff0009a";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FriSetupPolicy {
    /// Use the fixed recursion setups embedded with Airbender and the registered guest's GPU caps.
    #[default]
    Bundled,
    /// Independently derive both fixed recursion setups and compare them before registering the guest.
    Recompute,
}

impl std::fmt::Display for FriSetupPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Bundled => "bundled",
            Self::Recompute => "recompute",
        })
    }
}

pub fn authenticated_program(source: ProgramSource) -> anyhow::Result<ProgramSource> {
    let (bin, text) = source
        .contents()
        .map_err(anyhow::Error::msg)
        .context("reading the configured guest program")?;
    ensure!(
        format!("{:x}", Sha256::digest(&bin)) == APP_BIN_SHA256,
        "Syscoin guest binary digest mismatch"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&text)) == APP_TEXT_SHA256,
        "Syscoin guest text digest mismatch"
    );
    Ok(ProgramSource::from_bytes(
        bin.into_owned(),
        text.into_owned(),
    ))
}

pub fn verify_recursion_snapshots() -> anyhow::Result<()> {
    let security = SecurityLevel::Security100.model();
    for layer in [RecursionLayer::Unrolled, RecursionLayer::Unified] {
        let derived = derive_recursion_setup(security, layer);
        ensure!(
            &derived == recursion_setup(security, layer),
            "{layer:?} Security100 setup differs from its embedded snapshot"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_sections_bind_the_exact_bytes_handed_to_the_prover() {
        let bin = include_bytes!("../../../multiblock_batch.bin").as_slice();
        let text = include_bytes!("../../../multiblock_batch.text").as_slice();
        let configured = authenticated_program(ProgramSource::from_bytes(bin, text)).unwrap();
        let (returned_bin, returned_text) = configured.contents().unwrap();
        assert_eq!(returned_bin.as_ref(), bin);
        assert_eq!(returned_text.as_ref(), text);
        assert!(authenticated_program(ProgramSource::from_bytes(text, bin)).is_err());
    }
}
