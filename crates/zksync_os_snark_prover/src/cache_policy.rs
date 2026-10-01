use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use sha2::{Digest, Sha256};

/// Host setup-cache lifetime. Warm remains the compatible default for every caller.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WrapperCachePolicy {
    #[default]
    Warm,
    /// CPU only: authenticate once, then release setup caches between proving jobs.
    CpuCold,
}

impl WrapperCachePolicy {
    pub fn validate_supported(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self != Self::CpuCold || (!cfg!(feature = "gpu") && cfg!(unix)),
            "cpu-cold wrapper caching requires a CPU-only Unix build"
        );
        Ok(())
    }

    pub(crate) fn retain<T>(self, value: T) -> Option<T> {
        match self {
            Self::Warm => Some(value),
            Self::CpuCold => {
                drop_then(value, || self.reclaim("wrapper_cache_retired"));
                None
            }
        }
    }

    /// Best-effort reclamation of already freed pages, never a proof or memory gate.
    /// Other platforms, warm callers and GPU builds keep their original behavior.
    pub(crate) fn reclaim(self, boundary: &'static str) {
        if !self.reclamation_supported() {
            return;
        }
        #[cfg(all(target_os = "linux", target_env = "gnu", not(feature = "gpu")))]
        {
            let started = std::time::Instant::now();
            let rss_before_kib = optional_rss_kib();
            // SAFETY: glibc's thread-safe call only releases allocator-owned free pages.
            // No application pointer, live proof or setup is accessed or modified.
            let trim_return = unsafe { libc::malloc_trim(0) };
            let rss_after_kib = optional_rss_kib();
            tracing::info!(
                boundary,
                ?rss_before_kib,
                ?rss_after_kib,
                trim_return,
                elapsed_seconds = started.elapsed().as_secs_f64(),
                "CPU-cold best-effort heap reclamation; not memory qualification"
            );
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu", not(feature = "gpu"))))]
        let _ = boundary;
    }

    fn reclamation_supported(self) -> bool {
        self == Self::CpuCold
            && cfg!(all(
                target_os = "linux",
                target_env = "gnu",
                not(feature = "gpu")
            ))
    }

    /// Retire the successful merge's setup before allocating a cold wrapper.
    /// Failed merges propagate unchanged; warm callers keep their combiner.
    pub(crate) fn retire_combiner_after_merge<T, P, E>(
        self,
        merged: Result<P, E>,
        combiner: &mut T,
        recreate: impl FnOnce() -> T,
    ) -> Result<P, E> {
        let proof = merged?;
        if self == Self::CpuCold {
            let retired = std::mem::replace(combiner, recreate());
            drop_then(retired, || self.reclaim("combiner_retired"));
        }
        Ok(proof)
    }

    /// Carry only the verified compression VK into a cold phase-3 wrapper.
    /// The old wrapper is dropped before reconstruction; failures never rebuild.
    pub(crate) fn prepare_phase_three<T, P, V, E>(
        self,
        compressed: Result<P, E>,
        mut wrapper: T,
        carry_vk: impl FnOnce(&mut T) -> Result<V, E>,
        rebuild: impl FnOnce(V) -> Result<T, E>,
    ) -> Result<(T, P), E> {
        let proof = compressed?;
        if self == Self::CpuCold {
            let vk = carry_vk(&mut wrapper)?;
            drop_then(wrapper, || self.reclaim("phase_one_two_wrapper_retired"));
            wrapper = rebuild(vk)?;
        }
        Ok((wrapper, proof))
    }
}

fn drop_then<T>(value: T, after_drop: impl FnOnce()) {
    drop(value);
    after_drop();
}

#[cfg(all(target_os = "linux", target_env = "gnu", not(feature = "gpu")))]
fn optional_rss_kib() -> Option<u64> {
    let mut status = String::new();
    File::open("/proc/self/status")
        .ok()?
        .take(65536)
        .read_to_string(&mut status)
        .ok()?;
    parse_rss_kib(&status)
}

#[cfg(any(
    test,
    all(target_os = "linux", target_env = "gnu", not(feature = "gpu"))
))]
fn parse_rss_kib(status: &str) -> Option<u64> {
    let mut fields = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))?
        .split_whitespace();
    (fields.next()? == "VmRSS:").then_some(())?;
    let rss = fields.next()?.parse().ok()?;
    (fields.next()? == "kB" && fields.next().is_none()).then_some(rss)
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, i64, i64),
}

impl FileIdentity {
    fn read(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            len: metadata.len(),
            #[cfg(unix)]
            unix: (
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }
}

#[derive(Debug)]
struct BoundFile {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    identity: FileIdentity,
    sha256: [u8; 32],
}

impl BoundFile {
    fn capture(path: &Path) -> anyhow::Result<Self> {
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("resolve bound input {path:?}"))?;
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_file(),
            "bound input must be a regular non-symlink file: {path:?}"
        );
        let identity = FileIdentity::read(&metadata);
        let mut file = File::open(path)?;
        anyhow::ensure!(
            FileIdentity::read(&file.metadata()?) == identity,
            "bound input changed while opening: {path:?}"
        );
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        anyhow::ensure!(
            FileIdentity::read(&file.metadata()?) == identity
                && FileIdentity::read(&fs::symlink_metadata(path)?) == identity
                && path.canonicalize()? == canonical_path,
            "bound input changed while hashing: {path:?}"
        );
        Ok(Self {
            requested_path: path.to_owned(),
            canonical_path,
            identity,
            sha256: digest.finalize().into(),
        })
    }

    fn verify(&self) -> anyhow::Result<()> {
        let current = Self::capture(&self.requested_path)?;
        anyhow::ensure!(
            current.canonical_path == self.canonical_path
                && current.identity == self.identity
                && current.sha256 == self.sha256,
            "cpu-cold input changed since pre-lease VK validation: {:?}",
            self.requested_path
        );
        Ok(())
    }
}

/// Task-owned inputs must remain unchanged across cold reconstruction. This is a
/// content/identity consistency check, not protection against a hostile same-UID writer.
pub(crate) struct BoundWrapperInputs([BoundFile; 3]);

impl BoundWrapperInputs {
    pub(crate) fn capture(bin: &Path, text: &Path, setup: &Path) -> anyhow::Result<Self> {
        Ok(Self([
            BoundFile::capture(bin)?,
            BoundFile::capture(text)?,
            BoundFile::capture(setup)?,
        ]))
    }

    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        for file in &self.0 {
            file.verify()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn cold_retires_cache_but_warm_keeps_it() {
        let dropped = Arc::new(AtomicUsize::new(0));
        assert!(WrapperCachePolicy::CpuCold
            .retain(Dropped(dropped.clone()))
            .is_none());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let warm = WrapperCachePolicy::Warm.retain(Dropped(dropped.clone()));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        drop(warm);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn reclamation_observer_runs_only_after_owned_drop() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));
        drop_then(Dropped(dropped.clone()), || {
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            observed.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reclamation_is_only_explicit_cold_linux_gnu_cpu() {
        assert!(!WrapperCachePolicy::Warm.reclamation_supported());
        assert_eq!(
            WrapperCachePolicy::CpuCold.reclamation_supported(),
            cfg!(all(
                target_os = "linux",
                target_env = "gnu",
                not(feature = "gpu")
            ))
        );
        // On unsupported local platforms this must neither read /proc nor trim.
        if !WrapperCachePolicy::CpuCold.reclamation_supported() {
            WrapperCachePolicy::CpuCold.reclaim("unsupported_no_op_test");
        }
    }

    #[test]
    fn optional_rss_never_fabricates_or_requires_telemetry() {
        assert_eq!(parse_rss_kib("Name: test\nVmRSS:\t42 kB\n"), Some(42));
        for status in [
            "",
            "VmRSS: unavailable",
            "VmRSS: 1 MB",
            "VmRSS: 1 kB extra",
            "VmRSS: nope kB",
        ] {
            assert_eq!(parse_rss_kib(status), None);
        }
    }

    #[test]
    fn cold_retires_owned_combiner_before_wrapper_allocation() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut combiner = Some(Dropped(dropped.clone()));
        let proof = WrapperCachePolicy::CpuCold
            .retire_combiner_after_merge(Ok::<_, ()>("merged proof"), &mut combiner, || None)
            .unwrap();
        // The production transition returns only after the old setup is dropped;
        // a caller can now allocate the wrapper without that owned setup.
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(combiner.is_none());
        assert_eq!(proof, "merged proof");
        let _wrapper_allocation = Dropped(dropped.clone());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn warm_keeps_owned_combiner_and_does_not_reconstruct() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut combiner = Some(Dropped(dropped.clone()));
        let proof = WrapperCachePolicy::Warm
            .retire_combiner_after_merge(Ok::<_, ()>("merged proof"), &mut combiner, || {
                panic!("warm combiner must not be reconstructed")
            })
            .unwrap();
        assert_eq!(proof, "merged proof");
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(combiner.is_some());
        drop(combiner);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_merge_preserves_owned_combiner_and_exact_error() {
        for policy in [WrapperCachePolicy::CpuCold, WrapperCachePolicy::Warm] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut combiner = Some(Dropped(dropped.clone()));
            let error = policy
                .retire_combiner_after_merge(
                    Err::<(), _>("exact merge error"),
                    &mut combiner,
                    || panic!("a failed merge must not reconstruct the combiner"),
                )
                .unwrap_err();
            assert_eq!(error, "exact merge error");
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            assert!(combiner.is_some());
            drop(combiner);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn cold_phase_three_drops_old_setup_before_rebuild_and_carries_exact_values() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let proof = Arc::new(vec![1_u8, 2, 3]);
        let expected_proof = proof.clone();
        let vk = Arc::new(vec![4_u8, 5, 6]);
        let expected_vk = vk.clone();
        let old = (Dropped(dropped.clone()), vk);
        let (new, carried_proof) = WrapperCachePolicy::CpuCold
            .prepare_phase_three(
                Ok::<_, ()>(proof),
                old,
                |wrapper| Ok(wrapper.1.clone()),
                |carried_vk| {
                    assert_eq!(dropped.load(Ordering::SeqCst), 1);
                    assert!(Arc::ptr_eq(&carried_vk, &expected_vk));
                    Ok((Dropped(dropped.clone()), carried_vk))
                },
            )
            .unwrap();
        assert!(Arc::ptr_eq(&carried_proof, &expected_proof));
        assert!(Arc::ptr_eq(&new.1, &expected_vk));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        drop(new);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn warm_phase_three_keeps_wrapper_without_vk_carry_or_rebuild() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (wrapper, proof) = WrapperCachePolicy::Warm
            .prepare_phase_three(
                Ok::<_, ()>("verified compression"),
                Dropped(dropped.clone()),
                |_| -> Result<(), ()> { panic!("warm must not carry a replacement VK") },
                |_| -> Result<Dropped, ()> { panic!("warm must not rebuild") },
            )
            .unwrap();
        assert_eq!(proof, "verified compression");
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(wrapper);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_compression_never_carries_vk_or_allocates_phase_three() {
        for policy in [WrapperCachePolicy::CpuCold, WrapperCachePolicy::Warm] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let result = policy.prepare_phase_three(
                Err::<(), _>("exact compression error"),
                Dropped(dropped.clone()),
                |_| -> Result<(), &str> { panic!("failed compression must not carry a VK") },
                |_| -> Result<Dropped, &str> { panic!("failed compression must not rebuild") },
            );
            assert!(matches!(result, Err("exact compression error")));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn cold_vk_carry_failure_drops_owned_wrapper_without_rebuild() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let result = WrapperCachePolicy::CpuCold.prepare_phase_three(
            Ok::<_, &str>("verified compression"),
            Dropped(dropped.clone()),
            |_| -> Result<(), &str> { Err("exact VK error") },
            |_| -> Result<Dropped, &str> { panic!("failed VK must not rebuild") },
        );
        assert!(matches!(result, Err("exact VK error")));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn policy_preserves_default_and_rejects_gpu_cold() {
        assert_eq!(WrapperCachePolicy::default(), WrapperCachePolicy::Warm);
        assert!(WrapperCachePolicy::Warm.validate_supported().is_ok());
        assert_eq!(
            WrapperCachePolicy::CpuCold.validate_supported().is_ok(),
            !cfg!(feature = "gpu") && cfg!(unix)
        );
    }

    #[test]
    fn input_binding_rejects_mutation_replacement_and_symlinks() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "snark-cold-binding-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input");
        fs::write(&path, b"first").unwrap();
        let bound = BoundFile::capture(&path).unwrap();
        bound.verify().unwrap();
        fs::write(&path, b"other").unwrap();
        assert!(bound.verify().is_err());
        let replacement = directory.join("replacement");
        fs::write(&replacement, b"other").unwrap();
        let bound = BoundFile::capture(&path).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(bound.verify().is_err());
        #[cfg(unix)]
        {
            let link = directory.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(BoundFile::capture(&link).is_err());
            fs::remove_file(link).unwrap();
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
