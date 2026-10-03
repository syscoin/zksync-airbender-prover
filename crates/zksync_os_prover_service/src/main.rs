use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::watch;
use zksync_os_fri_prover::FriSetupPolicy;
use zksync_os_prover_service::{init_tracing, metrics};
use zksync_os_snark_prover::BinaryCommitmentPolicy;
use zksync_sequencer_proof_client::wait_for_operator_shutdown;

#[derive(Parser)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
struct Cli {
    #[command(flatten)]
    args: zksync_os_prover_service::Args,
    /// Fixed app commitment: bundled (default), or recompute from the pinned binaries.
    #[arg(
        long,
        env = "ZKSYNC_SNARK_BINARY_COMMITMENT_POLICY",
        value_enum,
        default_value_t = BinaryCommitmentPolicy::default()
    )]
    binary_commitment_policy: BinaryCommitmentPolicy,
    /// FRI setup summaries: bundled (default), or recompute on CPU.
    #[arg(
        long,
        env = "ZKSYNC_FRI_SETUP_POLICY",
        value_enum,
        default_value_t = FriSetupPolicy::default()
    )]
    fri_setup_policy: FriSetupPolicy,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    init_tracing();
    let Cli {
        args,
        binary_commitment_policy,
        fri_setup_policy,
    } = Cli::parse();

    // SYSCOIN: One cooperative stop signal owns the service and metrics tasks through shutdown.
    let (stop_sender, stop_receiver) = watch::channel(false);
    let service_stop_receiver = stop_receiver.clone();

    let prometheus_port = args.prometheus_port;

    let mut metrics_handle = tokio::spawn(async move {
        metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
    });
    let mut service = Box::pin(zksync_os_prover_service::run_with_setup_policies(
        args,
        service_stop_receiver,
        binary_commitment_policy,
        fri_setup_policy,
    ));

    let (service_result, metrics_task_finished) = tokio::select! {
        result = &mut service => {
            match &result {
                Ok(_) => tracing::info!("Zksync OS Prover Service finished successfully"),
                Err(e) => tracing::error!("Zksync OS Prover Service finished with error: {e:#}"),
            }
            stop_sender.send_replace(true);
            (result, false)
        }
        metrics_result = &mut metrics_handle => {
            let result = match metrics_result {
                Ok(Ok(())) => Err(anyhow::anyhow!("metrics exporter stopped unexpectedly")),
                Ok(Err(e)) => Err(e).context("metrics exporter failed"),
                Err(join_err) => Err(anyhow::anyhow!(
                    "metrics task panicked or was cancelled: {join_err}"
                )),
            };
            stop_sender.send_replace(true);
            // SYSCOIN: Stop queue polling cooperatively and retain any currently leased proof
            // through submission even when the auxiliary exporter fails.
            if let Err(service_err) = service.await {
                tracing::error!("Prover service also failed during metrics shutdown: {service_err:#}");
            }
            (result, true)
        }
        // SYSCOIN: Honor both interactive SIGINT and the SIGTERM used by production supervisors.
        signal = wait_for_operator_shutdown() => {
            tracing::info!("Operator stop request received; waiting for any in-flight proof to finish");
            stop_sender.send_replace(true);
            // SYSCOIN: Dropping `run` here could abandon an acquired FRI or SNARK lease.
            let service_result = service.await;
            let result = match signal {
                Ok(()) => service_result,
                Err(error) => Err(error),
            };
            (result, false)
        },
    };

    if !metrics_task_finished {
        match tokio::time::timeout(Duration::from_secs(10), &mut metrics_handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                tracing::error!("Metrics exporter failed while shutting down: {e:#}");
            }
            Ok(Err(join_err)) => {
                tracing::warn!("metrics task panicked or was cancelled: {join_err}");
            }
            Err(e) => {
                tracing::error!("Metrics exporter timed out while shutting down, aborting: {e}");
                metrics_handle.abort();
            }
        }
    }

    service_result
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, FromArgMatches};

    use super::*;

    fn parse_cli(policy: Option<&str>) -> Result<Cli, clap::Error> {
        parse_policies(policy, None)
    }

    fn parse_policies(policy: Option<&str>, fri_policy: Option<&str>) -> Result<Cli, clap::Error> {
        // Do not let an operator's environment choose the policy under test.
        let command = Cli::command()
            .mut_arg("binary_commitment_policy", |arg| arg.env(None::<&str>))
            .mut_arg("fri_setup_policy", |arg| arg.env(None::<&str>));
        let mut arguments = vec![
            "prover-service",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/combined-prover-commitment-test-submissions",
        ];
        if let Some(policy) = policy {
            arguments.extend(["--binary-commitment-policy", policy]);
        }
        if let Some(policy) = fri_policy {
            arguments.extend(["--fri-setup-policy", policy]);
        }
        let matches = command.try_get_matches_from(arguments)?;
        Cli::from_arg_matches(&matches)
    }

    #[test]
    fn bundled_commitment_is_the_combined_cli_default() {
        let cli = parse_cli(None).expect("default CLI must parse");
        assert_eq!(
            cli.binary_commitment_policy,
            BinaryCommitmentPolicy::Bundled
        );
        assert_eq!(cli.args.trusted_setup_file, "setup.key");
        assert_eq!(cli.fri_setup_policy, FriSetupPolicy::Bundled);
    }

    #[test]
    fn combined_cli_accepts_only_explicit_commitment_policies() {
        for (argument, expected) in [
            ("bundled", BinaryCommitmentPolicy::Bundled),
            ("recompute", BinaryCommitmentPolicy::Recompute),
        ] {
            assert_eq!(
                parse_cli(Some(argument))
                    .expect("documented policy must parse")
                    .binary_commitment_policy,
                expected
            );
        }
        assert!(parse_cli(Some("unknown")).is_err());
    }

    #[test]
    fn combined_commitment_policy_uses_the_shared_environment_option() {
        let command = Cli::command();
        let argument = command
            .get_arguments()
            .find(|argument| argument.get_id() == "binary_commitment_policy")
            .expect("commitment policy argument");
        assert_eq!(
            argument.get_env(),
            Some(std::ffi::OsStr::new(
                "ZKSYNC_SNARK_BINARY_COMMITMENT_POLICY"
            ))
        );
    }

    #[test]
    fn combined_fri_setup_policy_is_independent_and_explicit() {
        for snark in ["bundled", "recompute"] {
            assert_eq!(
                parse_policies(Some(snark), None).unwrap().fri_setup_policy,
                FriSetupPolicy::Bundled
            );
            for (argument, expected) in [
                ("bundled", FriSetupPolicy::Bundled),
                ("recompute", FriSetupPolicy::Recompute),
            ] {
                let cli = parse_policies(Some(snark), Some(argument)).unwrap();
                assert_eq!(cli.fri_setup_policy, expected);
                assert_eq!(cli.binary_commitment_policy.to_string(), snark);
            }
        }
        assert!(parse_policies(None, Some("auto")).is_err());
        let command = Cli::command();
        let argument = command
            .get_arguments()
            .find(|arg| arg.get_id() == "fri_setup_policy")
            .unwrap();
        assert_eq!(
            argument.get_env(),
            Some(std::ffi::OsStr::new("ZKSYNC_FRI_SETUP_POLICY"))
        );
    }
}
