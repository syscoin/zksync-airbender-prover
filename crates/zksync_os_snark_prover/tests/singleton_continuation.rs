use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use std::path::Path;
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_os_snark_prover::{create_combiner, merge_fris};
use zksync_sequencer_proof_client::{L2BatchNumber, SnarkProofInputs};

fn carried(proof: &UnrolledProgramProof) -> ProgramCommitment {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = proof.register_final_values[18 + i].value;
    }
    ProgramCommitment(words)
}

/// Exercises the real first-pass singleton path used for upgrade/security boundaries.
///
/// The fixture must be a valid Security100 V8 proof that is one unified fold short. The test
/// proves one extra ordinary unified pass, requires the settlement output to remain unchanged,
/// and requires the resulting carried commitment to be wrapper-ready.
///
/// ```bash
/// FRI_SINGLETON_FIXTURE=/path/to/first_pass_fri_proof.json \
///   cargo test -p zksync_os_snark_prover --release -- --ignored singleton_continuation
/// ```
#[test]
#[ignore = "needs a real first-pass Security100 FRI fixture and performs recursion proving"]
fn singleton_continuation_preserves_output_and_becomes_wrapper_ready() {
    let fixture = std::env::var("FRI_SINGLETON_FIXTURE")
        .expect("set FRI_SINGLETON_FIXTURE to a first-pass UnrolledProgramProof");
    let proof: UnrolledProgramProof = serde_json::from_reader(
        std::fs::File::open(Path::new(&fixture)).expect("cannot open FRI_SINGLETON_FIXTURE"),
    )
    .expect("cannot deserialize FRI_SINGLETON_FIXTURE as an UnrolledProgramProof");

    let versions = SupportedProtocolVersions::default();
    let vk_hash = versions
        .vk_hashes()
        .into_iter()
        .next()
        .expect("canonical VK");
    let expected = versions
        .program_commitment_for(&vk_hash)
        .expect("canonical program commitment");
    assert_ne!(
        carried(&proof),
        expected,
        "fixture must exercise the one-fold-short singleton path"
    );
    let original_output: Vec<_> = proof.register_final_values[..16]
        .iter()
        .map(|word| word.value)
        .collect();

    let input = SnarkProofInputs {
        from_batch_number: L2BatchNumber(1),
        to_batch_number: L2BatchNumber(1),
        vk_hash,
        fri_proofs: vec![proof],
    };
    let normalized = merge_fris(input, &mut create_combiner(), expected)
        .expect("singleton continuation must prove and verify");

    assert_eq!(carried(&normalized), expected);
    assert_eq!(
        normalized.register_final_values[..16]
            .iter()
            .map(|word| word.value)
            .collect::<Vec<_>>(),
        original_output,
        "singleton continuation changed the settlement public output"
    );
}
