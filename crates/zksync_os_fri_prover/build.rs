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
        "{}\ne8f380777b7e90388c7323d6fd80a3b58c589f17\n799e018339df40d0e456ba3fa0fc768ce0691853\n51ac41a846c976b25056f6857b62f133f347f4ca\nad6a5ad3c0254b0a15da528d209aacbb68ab0ebf\n",
        workspace.display()
    );
    let actual = fs::read_to_string(&marker)
        .expect("proving sources were not prepared; use scripts/cargo-with-patched-airbender.sh");
    assert_eq!(actual, expected, "unknown prepared proving sources");
    println!("cargo:rerun-if-changed={}", marker.display());
}
