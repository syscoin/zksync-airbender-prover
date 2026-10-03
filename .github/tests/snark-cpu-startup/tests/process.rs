use std::process::{Command, Output};

fn run(policy: &str, cpus: &str, threads: &str, backend: &str, env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_snark-cpu-startup-check"));
    command
        .env_remove("RAYON_NUM_THREADS")
        .env_remove("BELLMAN_NUM_THREADS")
        .env_remove("OMP_NUM_THREADS");
    command
        .args([policy, cpus, threads, backend])
        .envs(env.iter().copied());
    command.output().unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn inherit_preserves_environment() {
    let output = success(run(
        "inherit",
        "31",
        "16",
        "gpu",
        &[("RAYON_NUM_THREADS", "7")],
    ));
    assert!(output.contains("RAYON_NUM_THREADS=7\n"));
    assert!(output.contains("BELLMAN_NUM_THREADS=<unset>\n"));
    #[cfg(target_os = "linux")]
    assert_eq!(field(&output, "BEFORE"), field(&output, "AFTER"));
}

#[test]
fn cpu_fallback_is_unchanged_and_explicit_bounded_is_rejected() {
    let output = success(run("auto", "31", "16", "cpu", &[]));
    assert!(output.contains("settings inherited"));
    assert!(output.contains("RAYON_NUM_THREADS=<unset>\n"));
    assert!(!run("bounded", "31", "16", "cpu", &[]).status.success());
}

#[test]
fn zero_limits_are_rejected() {
    for (cpus, threads) in [("0", "16"), ("31", "0")] {
        assert!(!run("bounded", cpus, threads, "gpu", &[]).status.success());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_inherits_or_rejects_explicit_bounded() {
    assert!(success(run("auto", "31", "16", "gpu", &[])).contains("settings inherited"));
    assert!(!run("bounded", "31", "16", "gpu", &[]).status.success());
}

#[cfg(target_os = "linux")]
fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap()
}

#[cfg(target_os = "linux")]
fn cpus(value: &str) -> std::collections::BTreeSet<usize> {
    value
        .split(',')
        .flat_map(|part| {
            let (start, end) = part.split_once('-').unwrap_or((part, part));
            start.parse().unwrap()..=end.parse().unwrap()
        })
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_narrows_only_this_process_and_defaults_threads() {
    let output = success(run("bounded", "1", "16", "gpu", &[]));
    let before = cpus(field(&output, "BEFORE"));
    let after = cpus(field(&output, "AFTER"));
    assert_eq!(after.len(), 1);
    assert!(after.is_subset(&before));
    for name in [
        "RAYON_NUM_THREADS",
        "BELLMAN_NUM_THREADS",
        "OMP_NUM_THREADS",
    ] {
        assert_eq!(field(&output, name), "1");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn existing_library_specific_thread_values_are_preserved() {
    let output = success(run(
        "bounded",
        "1",
        "16",
        "gpu",
        &[("RAYON_NUM_THREADS", "7"), ("OMP_NUM_THREADS", "3")],
    ));
    assert_eq!(field(&output, "RAYON_NUM_THREADS"), "7");
    assert_eq!(field(&output, "OMP_NUM_THREADS"), "3");
    assert_eq!(field(&output, "BELLMAN_NUM_THREADS"), "1");
    let output = success(run(
        "bounded",
        "1",
        "16",
        "gpu",
        &[("RAYON_NUM_THREADS", "0"), ("OMP_NUM_THREADS", "4,2")],
    ));
    assert_eq!(field(&output, "RAYON_NUM_THREADS"), "0");
    assert_eq!(field(&output, "OMP_NUM_THREADS"), "4,2");
}
