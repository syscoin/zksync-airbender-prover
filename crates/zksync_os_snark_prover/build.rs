use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest path"));
    let workspace = manifest.join("../..").canonicalize().expect("workspace");
    let pins = workspace.join("patches/v2-proving-sources.json");
    let marker = workspace.join(".syscoin-proving-sources-prepared");
    let expected = format!(
        "{}\n{}",
        workspace.display(),
        fs::read_to_string(&pins).expect("source pins")
    );
    let actual = fs::read_to_string(&marker).expect("use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", pins.display());
    println!("cargo:rerun-if-changed={}", marker.display());
}
