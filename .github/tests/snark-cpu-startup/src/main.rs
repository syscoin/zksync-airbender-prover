#[path = "../../../../crates/zksync_os_snark_prover/src/cpu_startup.rs"]
mod cpu_startup;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let config = cpu_startup::Config {
        policy: args[1].parse()?,
        max_logical: args[2].parse()?,
        default_threads: args[3].parse()?,
    };
    #[cfg(target_os = "linux")]
    let before = allowed_cpus();
    // SAFETY: The harness runs as its own single-threaded child process, not in
    // the parallel test runner. It has not initialized libraries or runtimes.
    let report = unsafe { cpu_startup::apply(config, args[4] == "gpu") }?;
    println!("{report}");
    for name in [
        "RAYON_NUM_THREADS",
        "BELLMAN_NUM_THREADS",
        "OMP_NUM_THREADS",
    ] {
        println!(
            "{name}={}",
            std::env::var(name).unwrap_or_else(|_| "<unset>".into())
        );
    }
    #[cfg(target_os = "linux")]
    {
        let after = allowed_cpus();
        let inherited = std::thread::spawn(allowed_cpus).join().unwrap();
        assert_eq!(after, inherited, "new threads must inherit the policy");
        println!("BEFORE={before}");
        println!("AFTER={after}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn allowed_cpus() -> String {
    // /proc/thread-self observes the calling thread, unlike /proc/self/status.
    std::fs::read_to_string("/proc/thread-self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim()
        .to_owned()
}
