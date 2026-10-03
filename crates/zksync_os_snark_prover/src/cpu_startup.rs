//! SYSCOIN: Process-only tuning, applied before tracing, Tokio or proving threads exist.
//! This module must not be called from the shared prover library or a running service.

#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, BTreeSet};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Auto,
    Bounded,
    Inherit,
}

impl std::str::FromStr for Policy {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "bounded" => Ok(Self::Bounded),
            "inherit" => Ok(Self::Inherit),
            _ => Err("CPU policy must be auto, bounded or inherit"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub policy: Policy,
    pub max_logical: usize,
    pub default_threads: usize,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug)]
struct Cpu {
    logical: usize,
    package: i32,
    core: i32,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    cpus: Vec<usize>,
    threads: usize,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(any(target_os = "linux", test))]
fn plan(config: Config, topology: &[Cpu], online: &[usize], capacity: usize) -> Option<Plan> {
    let mut cores = BTreeMap::<(i32, i32), Vec<usize>>::new();
    let allowed: BTreeSet<_> = topology.iter().map(|cpu| cpu.logical).collect();
    for cpu in topology {
        cores
            .entry((cpu.package, cpu.core))
            .or_default()
            .push(cpu.logical);
    }
    let measured_topology = allowed.len() == 48
        && cores.len() == 24
        && cores.values().all(|siblings| siblings.len() == 2)
        && topology
            .iter()
            .map(|cpu| cpu.package)
            .collect::<BTreeSet<_>>()
            .len()
            == 1
        && allowed == online.iter().copied().collect()
        && capacity >= 48;
    if config.policy == Policy::Inherit || (config.policy == Policy::Auto && !measured_topology) {
        return None;
    }
    // Prefer one allowed CPU per physical core, then allowed SMT siblings. Never
    // assume CPU numbering, contiguous cpusets, or that CPU 0 is available.
    let mut primary = Vec::new();
    let mut siblings = Vec::new();
    for group in cores.values_mut() {
        group.sort_unstable();
        primary.push(group[0]);
        siblings.extend_from_slice(&group[1..]);
    }
    primary.sort_unstable();
    siblings.sort_unstable();
    primary.extend(siblings);
    primary.truncate(config.max_logical);
    primary.sort_unstable();
    let threads = config.default_threads.min(primary.len()).min(capacity);
    Some(Plan {
        cpus: primary,
        threads,
    })
}

#[cfg(target_os = "linux")]
const THREAD_VARS: [&str; 3] = [
    "RAYON_NUM_THREADS",
    "BELLMAN_NUM_THREADS",
    "OMP_NUM_THREADS",
];

#[cfg(target_os = "linux")]
fn thread_environment(default: usize) -> Vec<(&'static str, std::ffi::OsString, bool)> {
    THREAD_VARS
        .iter()
        .map(|&name| match std::env::var_os(name) {
            // Each library owns its grammar (e.g. Rayon permits 0 and OpenMP
            // permits nested thread lists). Do not reinterpret operator values.
            Some(value) => (name, value, false),
            None => (name, default.to_string().into(), true),
        })
        .collect()
}

/// Apply only from single-threaded executable startup, before any library may
/// spawn threads or read the process environment concurrently.
///
/// # Safety
/// The caller must ensure there are no other threads for the duration of this
/// call. New threads must be created afterwards to inherit the narrowed mask.
pub unsafe fn apply(config: Config, gpu: bool) -> io::Result<String> {
    if config.max_logical == 0 || config.default_threads == 0 {
        return Err(invalid("CPU limits must be positive"));
    }
    if config.policy == Policy::Inherit {
        return Ok("inherit: affinity and thread environment unchanged".into());
    }
    if !gpu || !cfg!(target_os = "linux") {
        if config.policy == Policy::Bounded {
            return Err(invalid(
                "bounded CPU policy requires a Linux GPU SNARK worker",
            ));
        }
        return Ok("auto: CPU-only/unsupported platform; settings inherited".into());
    }
    #[cfg(target_os = "linux")]
    {
        let detected = linux::detect();
        let (topology, online, capacity) = match detected {
            Ok(value) => value,
            Err(error) if config.policy == Policy::Auto => {
                return Ok(format!(
                    "auto: topology/affinity detection unavailable ({error}); settings inherited"
                ));
            }
            Err(error) => return Err(error),
        };
        let Some(plan) = plan(config, &topology, &online, capacity) else {
            return Ok("auto: outside measured unrestricted 24-core/48-thread topology; settings inherited".into());
        };
        if plan.cpus.is_empty() || plan.threads == 0 {
            return Err(invalid("CPU policy selected no usable CPUs/threads"));
        }
        let environment = thread_environment(plan.threads);
        linux::set_affinity(&plan.cpus)?;
        if linux::affinity()? != plan.cpus {
            return Err(io::Error::other(
                "effective CPU affinity changed during startup; refusing to start",
            ));
        }
        for (name, value, missing) in &environment {
            if *missing {
                // SAFETY: apply's caller guarantees single-threaded startup.
                unsafe { std::env::set_var(name, value) };
            }
        }
        Ok(format!(
            "{:?}: effective logical CPUs {:?}; detected capacity {}; thread environment {:?}; explicit Airbender pool follows affinity, not RAYON_NUM_THREADS",
            config.policy, plan.cpus, capacity, environment.iter().map(|(name, value, _)| (*name, value)).collect::<Vec<_>>()
        ))
    }
    #[cfg(not(target_os = "linux"))]
    unreachable!("unsupported platform returned before tuning")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{fs, mem};

    pub(super) fn affinity() -> io::Result<Vec<usize>> {
        // Dynamic storage avoids silently truncating masks above CPU_SETSIZE.
        let mut words = vec![0usize; 128 / mem::size_of::<usize>()];
        loop {
            let bytes = words.len() * mem::size_of::<usize>();
            // SAFETY: aligned writable storage of exactly bytes bytes; pid 0 is self.
            if unsafe { libc::sched_getaffinity(0, bytes, words.as_mut_ptr().cast()) } == 0 {
                let cpus = words
                    .iter()
                    .enumerate()
                    .flat_map(|(index, word)| {
                        (0..usize::BITS as usize).filter_map(move |bit| {
                            (word & (1usize << bit) != 0)
                                .then_some(index * usize::BITS as usize + bit)
                        })
                    })
                    .collect::<Vec<_>>();
                if cpus.is_empty() {
                    return Err(invalid("empty allowed CPU mask"));
                }
                return Ok(cpus);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) || bytes >= 1024 * 1024 {
                return Err(error);
            }
            words.resize(words.len() * 2, 0);
        }
    }

    pub(super) fn set_affinity(cpus: &[usize]) -> io::Result<()> {
        let maximum = *cpus
            .last()
            .ok_or_else(|| invalid("empty selected CPU mask"))?;
        let mut words =
            vec![0usize; (maximum / usize::BITS as usize + 1).max(128 / mem::size_of::<usize>())];
        for &cpu in cpus {
            words[cpu / usize::BITS as usize] |= 1usize << (cpu % usize::BITS as usize);
        }
        // SAFETY: aligned initialized storage of the advertised length; pid 0 is self.
        if unsafe {
            libc::sched_setaffinity(
                0,
                words.len() * mem::size_of::<usize>(),
                words.as_ptr().cast(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn parse_cpu_list(value: &str) -> io::Result<Vec<usize>> {
        let mut cpus = BTreeSet::new();
        for range in value.trim().split(',') {
            let (start, end) = range.split_once('-').unwrap_or((range, range));
            let start: usize = start
                .parse()
                .map_err(|_| invalid("invalid online CPU list"))?;
            let end: usize = end
                .parse()
                .map_err(|_| invalid("invalid online CPU list"))?;
            if start > end || end >= 8 * 1024 * 1024 {
                return Err(invalid("unsupported online CPU list"));
            }
            cpus.extend(start..=end);
        }
        Ok(cpus.into_iter().collect())
    }

    pub(super) fn detect() -> io::Result<(Vec<Cpu>, Vec<usize>, usize)> {
        let allowed = affinity()?;
        let topology = allowed
            .into_iter()
            .map(|logical| {
                let root = format!("/sys/devices/system/cpu/cpu{logical}/topology");
                let read = |name| -> io::Result<i32> {
                    let value = fs::read_to_string(format!("{root}/{name}"))?;
                    value
                        .trim()
                        .parse::<i32>()
                        .ok()
                        .filter(|n| *n >= 0)
                        .ok_or_else(|| invalid("invalid CPU topology"))
                };
                Ok(Cpu {
                    logical,
                    package: read("physical_package_id")?,
                    core: read("core_id")?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let online = parse_cpu_list(&fs::read_to_string("/sys/devices/system/cpu/online")?)?;
        let capacity = std::thread::available_parallelism()?.get();
        Ok((topology, online, capacity))
    }

    #[test]
    fn online_cpu_ranges_are_bounded() {
        assert_eq!(
            parse_cpu_list("0-3,7,12-13\n").unwrap(),
            [0, 1, 2, 3, 7, 12, 13]
        );
        for bad in ["", "2-1", "a", "0-999999999", "1-"] {
            assert!(parse_cpu_list(bad).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(policy: Policy) -> Config {
        Config {
            policy,
            max_logical: 31,
            default_threads: 16,
        }
    }

    fn measured() -> Vec<Cpu> {
        (0..48)
            .map(|logical| Cpu {
                logical,
                package: 0,
                core: (logical % 24) as i32,
            })
            .collect()
    }

    #[test]
    fn auto_reproduces_measured_mask_and_environment_defaults() {
        assert_eq!(
            plan(
                config(Policy::Auto),
                &measured(),
                &(0..48).collect::<Vec<_>>(),
                48
            ),
            Some(Plan {
                cpus: (0..31).collect(),
                threads: 16
            })
        );
    }

    #[test]
    fn auto_does_not_guess_on_other_allocations() {
        let all = measured();
        let online: Vec<_> = (0..48).collect();
        assert!(plan(config(Policy::Auto), &all, &online, 24).is_none());
        assert!(plan(config(Policy::Auto), &all[4..], &online, 48).is_none());
        assert!(plan(config(Policy::Auto), &all, &(0..96).collect::<Vec<_>>(), 48).is_none());
        let mut two_sockets = all.clone();
        for cpu in &mut two_sockets {
            cpu.package = (cpu.logical % 2) as i32;
        }
        assert!(plan(config(Policy::Auto), &two_sockets, &online, 48).is_none());
        assert!(plan(config(Policy::Inherit), &all, &online, 48).is_none());
    }

    #[test]
    fn selection_is_physical_first_and_respects_sparse_allowed_mask() {
        let topology = [
            Cpu {
                logical: 8,
                package: 0,
                core: 0,
            },
            Cpu {
                logical: 9,
                package: 0,
                core: 0,
            },
            Cpu {
                logical: 32,
                package: 0,
                core: 1,
            },
            Cpu {
                logical: 33,
                package: 0,
                core: 1,
            },
            Cpu {
                logical: 2048,
                package: 1,
                core: 0,
            },
        ];
        let selected = plan(
            Config {
                max_logical: 3,
                ..config(Policy::Bounded)
            },
            &topology,
            &[],
            2,
        )
        .unwrap();
        assert_eq!(
            selected,
            Plan {
                cpus: vec![8, 32, 2048],
                threads: 2
            }
        );
    }

    #[test]
    fn bounded_never_adds_cpus_to_small_allocation() {
        let selected = plan(config(Policy::Bounded), &measured()[37..40], &[], 48).unwrap();
        assert_eq!(
            selected,
            Plan {
                cpus: vec![37, 38, 39],
                threads: 3
            }
        );
    }

    #[test]
    fn policy_parse_is_strict() {
        assert_eq!("bounded".parse::<Policy>().unwrap(), Policy::Bounded);
        assert!("automatic".parse::<Policy>().is_err());
    }
}
