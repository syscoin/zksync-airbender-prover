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
        "{}\n99c0b6d2d935828e1f4ff89acfc9e33d21d40f59\n169b0b599bd18c8f992e7e0cf168403b475588b2\na1e9a551b9588b1dfab5c5088554fc69770c0e85\nc52391d0df82126d27e5c76810e9df85c61875d0\n",
        workspace.display()
    );
    let actual = fs::read_to_string(&marker)
        .expect("proving sources were not prepared; use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", marker.display());
}
