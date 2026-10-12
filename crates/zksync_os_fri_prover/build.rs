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
        "{}\n553fdd31b9d7a0b354845c7b6b8e7c3d13337c52\n6693fdafa31c45ebf8acf26e9a1f3dfc3edcffdc\n914a0cd1402f289cabccd83cf6cafa1c148385ad\nf8d7b132a841e0bfbfccd27614314a279d523887\n",
        workspace.display()
    );
    let actual = fs::read_to_string(&marker)
        .expect("proving sources were not prepared; use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", marker.display());
}
