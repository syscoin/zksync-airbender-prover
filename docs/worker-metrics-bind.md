# Standalone worker metrics binding

The standalone FRI worker and `zksync_os_snark_prover run-prover` accept
`--prometheus-bind-address <IP>` alongside their existing `--prometheus-port`.
Defaults remain `0.0.0.0:3125` for FRI and `0.0.0.0:3126` for SNARK, preserving
existing remote monitoring. Only literal IPv4 or IPv6 addresses are accepted;
IPv6 support depends on the host network configuration.

For private local or SSH-forwarded monitoring, pass
`--prometheus-bind-address 127.0.0.1` explicitly and forward the metrics port over
the same reviewed private SSH connection. A tunnel alone does not restrict an
all-interface listener. This option does not change the sequencer endpoint,
transport policy, durable spool, proof verification, or worker resource settings.
The combined service is unchanged; these options apply to the two standalone
worker roles. No firewall change is needed for the loopback-bound listeners.
