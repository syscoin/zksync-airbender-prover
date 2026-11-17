//! Export the public inputs and EVM words of a saved production worker proof.
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use zkos_wrapper::SnarkWrapperProof;

#[derive(Parser)]
struct Args {
    proof: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let file = File::open(&args.proof).with_context(|| format!("open {}", args.proof.display()))?;
    let proof: SnarkWrapperProof = serde_json::from_reader(BufReader::new(file))?;
    let (public_inputs, words) = crypto_codegen::serialize_proof(&proof);
    let render = |value| format!("{value:#066x}");
    let output = serde_json::json!({
        "public_inputs": public_inputs.into_iter().map(render).collect::<Vec<_>>(),
        "proof": words.into_iter().map(render).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
