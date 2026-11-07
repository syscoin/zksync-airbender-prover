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
        "{}\n7f68838bf1b7d0c8f6b4848cf3a6c93cb3c2bc02\n2f2d38a11020844883d0e617bf476dd2430d3c2e\na1e9a551b9588b1dfab5c5088554fc69770c0e85\nc52391d0df82126d27e5c76810e9df85c61875d0\n",
        workspace.display()
    );
    let actual = fs::read_to_string(&marker)
        .expect("proving sources were not prepared; use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", marker.display());
}
