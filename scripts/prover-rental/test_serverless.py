import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import job
import runpod
import sentry
import serverless
import storage
from test_adapter import payload, release, storage_plan
from test_storage import S3, config as storage_config
from test_warm import MailboxStorage


def policy():
    return {"schema_version": 1, "endpoint_id": "endpoint-test", "template_id": "template-test",
            "image": "registry.example/prover-serverless@sha256:" + "7" * 64,
            "gpu_type_ids": ["NVIDIA GeForce RTX 5090"], "gpu_pools": ["BLACKWELL_32"],
            "allowed_cuda_versions": ["12.9"], "min_cuda_version": None, "gpu_count": 1,
            "workers_min": 0, "workers_max": 1, "flashboot": True, "idle_timeout_seconds": 5, "disk_gb": 100,
            "limits": {"max_runtime_seconds": 900, "startup_timeout_seconds": 600,
                       "result_retention_seconds": 1800, "max_hourly_usd": "2", "max_operation_usd": "2",
                       "lifetime_budget_usd": "10", "max_artifact_bytes": job.MAX_SUBMIT}}


class Api:
    def __init__(self, selected=None):
        selected = selected or policy()
        self.config = {"id": selected["endpoint_id"], "type": "QUEUE", "image": selected["image"],
            "flashboot": "FLASHBOOT", "workers": {"min": 0, "max": 1, "idleTimeout": 5},
            "gpu": {"count": 1, "pools": selected["gpu_pools"], "allowedCudaVersions": ["12.9"],
                    "minCudaVersion": None}, "disk": 100, "timeout": 900000,
            "args": "", "entrypoint": [], "cmd": [], "env": {}, "ports": [], "networkVolumes": [],
            "scaling": {"type": "QUEUE_DELAY", "queueDelay": 4}}
        self.legacy = {"id": selected["endpoint_id"], "templateId": selected["template_id"],
            "gpuTypeIds": selected["gpu_type_ids"], "gpuCount": 1, "computeType": "GPU",
            "template": {"id": selected["template_id"], "imageName": selected["image"], "isServerless": True}}
        self.calls, self.fail_submit, self.fail_status = [], False, False
        self.result = {"id": "run-test", "status": "IN_QUEUE"}

    def endpoint(self, endpoint_id):
        self.calls.append(("endpoint", endpoint_id))
        return copy.deepcopy(self.config)

    def legacy_endpoint(self, endpoint_id):
        self.calls.append(("legacy_endpoint", endpoint_id))
        return copy.deepcopy(self.legacy)

    def submit(self, endpoint_id, value):
        self.calls.append(("submit", endpoint_id, copy.deepcopy(value)))
        if self.fail_submit:
            raise runpod.Error("transport_failure")
        return copy.deepcopy(self.result)

    def status(self, endpoint_id, run_id):
        self.calls.append(("status", endpoint_id, run_id))
        if self.fail_status:
            raise runpod.HttpError(404)
        return copy.deepcopy(self.result)


def publish_result(objects, selected, operation_id, proof=None):
    proof = proof or {key: value for key, value in payload("FRI").items() if key != "prover_input"}
    proof["proof"] = base64.b64encode(b"p" * 41).decode()
    raw = job.encode(proof)
    objects.put(selected["result_artifact_url"], raw)
    result = {"schema_version": 1, "operation_id": operation_id, "job_id": selected["job_id"],
              "manifest_sha256": selected["manifest_sha256"], "artifact_sha256": job.hash_bytes(raw),
              "artifact_bytes": len(raw)}
    objects.put(selected["result_manifest_url"], job.encode(result))
    return result


class ServerlessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root, self.now = Path(self.temp.name), 1000
        self.store = serverless.ServerlessStore.initialize(self.root / "serverless", policy())
        self.api, self.objects = Api(), MailboxStorage()
        self.operation = "a" * 32
        self.plan = {"claim_get_url": "https://storage.example/claim?get=scoped",
                     "claim_put_url": "https://storage.example/claim?put=scoped"}
        self.directory = self.root / "input"
        sentry.export_input(self.directory, job.encode(payload("FRI")), job.encode(release("FRI")),
                            "job-a", storage_plan(), self.objects)
        self.selected = runpod.read_private_json(self.directory / "controller-job.json")

    def controller(self):
        return serverless.ServerlessController(self.store, self.api, clock=lambda: self.now, http=self.objects)

    def launch(self):
        return self.controller().launch(self.selected, self.operation, 1800, 60, self.plan)

    def posts(self):
        return [call for call in self.api.calls if call[0] == "submit"]

    def test_exact_endpoint_checked_before_post_and_queue_in_original_deadline(self):
        self.launch()
        sent = self.posts()[0][2]
        self.assertEqual(sent["policy"], {"executionTimeout": 800000, "ttl": 2600000})
        self.assertEqual(sent["input"]["deadline_unix"], 1800)
        self.assertEqual(sent["input"]["runtime_limit_seconds"], 60)
        self.assertEqual(self.api.calls[0][0], "endpoint")
        self.assertEqual(self.store.load()["reserved_usd"], "2")
        self.assertNotIn("pod_id", self.controller().operation(self.operation))

    def test_preflight_time_cannot_extend_original_compute_window(self):
        endpoint = self.api.legacy_endpoint
        def delayed(identifier):
            result = endpoint(identifier)
            self.now = 1790
            return result
        with patch.object(self.api, "legacy_endpoint", delayed), self.assertRaisesRegex(
                runpod.Error, "original_deadline_exceeded"):
            self.launch()
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.store.load()["reserved_usd"], "0")

    def test_endpoint_misconfiguration_never_allocates_or_reserves(self):
        cases = (("flashboot", "OFF"), ("workers", {"min": 1, "max": 1, "idleTimeout": 5}),
                 ("workers", {"min": 0, "max": 2, "idleTimeout": 5}),
                 ("workers", {"min": False, "max": True, "idleTimeout": 5}),
                 ("image", "mutable:latest"), ("env", {"RUNPOD_API_KEY": "secret"}),
                 ("args", "alternate-worker"), ("type", "LOAD_BALANCER"), ("timeout", 1000000))
        original = copy.deepcopy(self.api.config)
        for field, value in cases:
            self.api.config = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(runpod.Error):
                self.launch()
            self.assertEqual(self.posts(), [])
            self.assertEqual(self.store.load()["reserved_usd"], "0")

    def test_ambiguous_post_restart_never_reposts_or_releases_budget(self):
        self.api.fail_submit = True
        with self.assertRaisesRegex(runpod.Error, "submission_uncertain"):
            self.launch()
        self.now += 100
        self.assertEqual(self.launch(), self.operation)
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.store.load()["reserved_usd"], "2")
        with self.assertRaisesRegex(runpod.Error, "requires_reconciliation"):
            self.controller().check_capacity()
        self.now = 2000
        with self.assertRaisesRegex(runpod.Error, "deadline_not_elapsed"):
            self.controller().finish(self.operation, "expired")

    def test_durable_result_recovers_unknown_post_but_does_not_fake_provider_completion(self):
        self.api.fail_submit = True
        with self.assertRaises(runpod.Error):
            self.launch()
        result = publish_result(self.objects, self.selected, self.operation)
        controller = self.controller()
        self.assertTrue(controller.collect(self.operation))
        sentry.verify_input_result(self.directory, runpod.Store(self.store.root), self.operation,
                                   self.directory / "returned-proof.json")
        controller.finish(self.operation, "returned")
        self.assertIsNone(self.controller().operation(self.operation)["provider_job_id"])
        with self.assertRaises(runpod.Error):
            self.controller().check_capacity()
        self.api.result = {"id": "run-test", "status": "COMPLETED", "output": result}
        self.controller().bind_completed_run(self.operation, "run-test")
        self.assertEqual(self.store.load()["operations"], {})
        self.assertEqual(self.store.load()["reserved_usd"], "2")
        self.assertTrue(self.controller().has_job("job-a"))
        self.assertIs(self.controller().operation(self.operation)["receipt"]["proof_verified"], False)

    def test_provider_completed_without_durable_result_cannot_verify_or_finish(self):
        self.launch()
        self.api.result["status"] = "COMPLETED"
        controller = self.controller()
        controller.tick(self.operation)
        self.assertFalse(controller.collect(self.operation))
        with self.assertRaisesRegex(runpod.Error, "durable_artifact_required"):
            controller.finish(self.operation, "accepted")
        self.assertIsNone(self.controller().operation(self.operation)["disposition"])

    def test_404_is_unknown_not_terminal_and_cannot_expire(self):
        self.launch()
        self.now, self.api.fail_status = 2000, True
        controller = self.controller()
        controller.tick(self.operation)
        self.assertEqual(controller.operation(self.operation)["provider_status"], "ABSENT")
        with self.assertRaisesRegex(runpod.Error, "deadline_not_elapsed"):
            controller.finish(self.operation, "expired")
        self.assertEqual(self.store.load()["reserved_usd"], "2")

    def test_tampered_result_and_backend_journals_fail_closed(self):
        self.launch()
        result = publish_result(self.objects, self.selected, self.operation)
        result["manifest_sha256"] = "0" * 64
        self.objects.put(self.selected["result_manifest_url"], job.encode(result))
        with self.assertRaisesRegex(runpod.Error, "result_job_mismatch"):
            self.controller().collect(self.operation)
        runpod.atomic_json(self.store.root / "state.json", {"schema_version": 1})
        with self.assertRaisesRegex(runpod.Error, "ambiguous_provider_backend"):
            serverless.receipt_controller(runpod.Store(self.store.root))

    def test_budget_and_original_attempt_are_immutable(self):
        self.launch()
        with self.assertRaisesRegex(runpod.Error, "attempt_changed"):
            self.controller().launch(self.selected, self.operation, 1850, 60, self.plan)
        controller = self.controller()
        controller.state["reserved_usd"] = "10"
        controller.state["operations"] = {}
        controller.save()
        with self.assertRaisesRegex(runpod.Error, "budget_exhausted"):
            self.controller().check_capacity()

    def test_terminal_failure_expiry_preserves_lifetime_spend_and_history(self):
        self.launch()
        self.api.result["status"] = "TIMED_OUT"
        self.now = 1800
        controller = self.controller()
        controller.tick(self.operation)
        controller.finish(self.operation, "expired")
        self.assertEqual(self.store.load()["operations"], {})
        self.assertEqual(self.store.load()["reserved_usd"], "2")
        self.assertEqual(self.controller().operation(self.operation)["disposition"], "expired")
        self.assertTrue(self.controller().has_job("job-a"))

    def test_archive_crash_recovers_after_provider_status_retention_ends(self):
        self.launch()
        publish_result(self.objects, self.selected, self.operation)
        self.api.result["status"] = "COMPLETED"
        controller = self.controller()
        controller.collect(self.operation)
        controller.tick(self.operation)
        retain = self.store.retain_history
        def fail_index(name, value):
            if name.startswith("serverless-job-"):
                raise OSError("simulated index crash")
            retain(name, value)
        with patch.object(self.store, "retain_history", fail_index), self.assertRaises(OSError):
            controller.finish(self.operation, "returned")
        self.api.fail_status = True
        self.controller().check_capacity()
        self.assertEqual(self.store.load()["operations"], {})
        self.assertTrue(self.controller().has_job("job-a"))
        self.assertEqual(self.controller().operation(self.operation)["provider_status"], "COMPLETED")

    def test_status_redacts_capabilities_and_conditional_claim_is_signed(self):
        self.launch()
        encoded = job.encode(self.controller().status())
        self.assertNotIn(b"https://", encoded)
        self.assertNotIn(b"scoped", encoded)
        client = S3()
        selected = storage.S3Storage(storage_config(), client, clock=lambda: self.now)
        claim = selected.compute_claim_plan(self.operation)
        self.assertEqual(set(claim), {"claim_get_url", "claim_put_url"})
        conditional = [params for method, params, _ in client.signatures if method == "put_object"]
        self.assertEqual(conditional[0]["IfNoneMatch"], "*")
        self.assertEqual(len(selected.job_plan(self.operation)), 8)

    def test_invalid_marker_does_not_fallback_and_cuda_modes_are_exclusive(self):
        runpod.atomic_json(self.store.root / "serverless.json", {"schema_version": 1, "backend": "other"})
        with self.assertRaises(runpod.Error):
            serverless.receipt_controller(runpod.Store(self.store.root))
        selected = policy()
        selected["min_cuda_version"] = "12.9"
        with self.assertRaisesRegex(runpod.Error, "mutually_exclusive"):
            serverless.validate_policy(selected)
        for value in (0, 599, None):
            selected = policy()
            selected["limits"]["startup_timeout_seconds"] = value
            with self.subTest(value=value), self.assertRaises(runpod.Error):
                serverless.validate_policy(selected)


if __name__ == "__main__":
    unittest.main()
