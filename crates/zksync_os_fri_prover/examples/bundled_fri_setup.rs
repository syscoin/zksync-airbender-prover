//! Independently rederive the Security100 recursion snapshots embedded by V2.
use clap::Parser;
use zksync_os_fri_prover::setup_summaries::verify_recursion_snapshots;

#[derive(Parser)]
struct Args {
    /// Compare the re-derived public setups with the embedded release snapshots.
    #[arg(long, required = true)]
    verify: bool,
}

fn main() -> anyhow::Result<()> {
    Args::parse();
    std::thread::Builder::new()
        .name("verify-recursion-setups".to_owned())
        .stack_size(256 * 1024 * 1024)
        .spawn(verify_recursion_snapshots)?
        .join()
        .map_err(|_| anyhow::anyhow!("FRI setup verification panicked"))?
}
