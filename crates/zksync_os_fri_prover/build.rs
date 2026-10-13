use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest path"));
    let workspace = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("canonical prover workspace");
    let marker = workspace.join(".syscoin-proving-sources-prepared");
    let expected = format!(
        "{}\n0d8c852954afcae1f160151a17fe80886f1755b0\na41a4a18eeb102b405bcb63ad7ca85e9b6b13213\na1e9a551b9588b1dfab5c5088554fc69770c0e85\n4fda70a408c7817474fe67fba46b38cfbe420e59\n",
        workspace.display()
    );
    let actual = fs::read_to_string(&marker)
        .expect("proving sources were not prepared; use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", marker.display());
}
