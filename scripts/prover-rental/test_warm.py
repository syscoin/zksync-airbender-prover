import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import job
import runpod
import sentry
import warm_protocol as warm
import warm_worker
import worker
from test_adapter import Storage, payload, release, storage_plan, successful_native
from test_runpod import FakeApi, policy


def session():
    return {"schema_version": 1, "session_id": "5" * 32, "session_key": "6" * 64,
            "mailbox_url": "https://storage.example/mailbox?get=SESSION_ONLY",
            "finished_manifest_url": "https://storage.example/finished?get=SESSION_ONLY",
            "finished_manifest_put_url": "https://storage.example/finished?put=SESSION_ONLY",
            "poll_interval_seconds": 1}


class MailboxStorage(Storage):
    def __init__(self):
        super().__init__()
        self.fail_once_path = None

    def request(self, url, **kwargs):
        if kwargs.get("method", "GET") == "PUT":
            self.put(url, kwargs["data"], kwargs.get("deadline"))
            return 200, {}, b""
        key = self.key(url)
        if key not in self.objects:
            return 404, {}, b""
        return 200, {}, self.get(url, kwargs["maximum"])

    def json(self, url, limit=runpod.JSON_LIMIT):
        if self.key(url) not in self.objects:
            raise runpod.HttpError(404)
        return super().json(url, limit)

    def put(self, url, data, deadline=None):
        super().put(url, data, deadline)
        if self.key(url) == self.fail_once_path:
            self.fail_once_path = None
            raise runpod.Error("transport_failure")


class WarmSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = runpod.Store.initialize(self.root / "controller", policy())
        self.api, self.storage = FakeApi(), MailboxStorage()
        self.now = 1000
        self.store.heartbeat(self.now)
        self.lock = self.store.lock("watchdog.lock")
        self.lock.__enter__()
        self.addCleanup(self.lock.__exit__, None, None, None)
        self.releases = self.root / "releases"
        self.releases.mkdir()
        for stage in ("FRI", "SNARK"):
            job.write_new(self.releases / (stage + ".json"), job.encode(release(stage)))
        self.seen = []

    def controller(self):
        return runpod.Controller(self.store, self.api, lambda: self.now, self.storage)

    def launch(self):
        return self.controller().launch_session(session())

    def count(self, call):
        return len([value for value in self.api.calls if value[0] == call])

    def prepare(self, stage, number):
        attempt_id = format(number, "032x")
        plan = {name: url.replace("storage.example/", "storage.example/" + attempt_id + "/")
                for name, url in storage_plan().items()}
        directory = self.root / ("native-" + attempt_id)
        sentry.export_input(directory, job.encode(payload(stage)), job.encode(release(stage)),
                            "job-" + attempt_id, plan, self.storage)
        return attempt_id, runpod.read_private_json(directory / "controller-job.json")

    def publish(self, operation_id, stage="FRI", number=1):
        attempt_id, selected = self.prepare(stage, number)
        controller = self.controller()
        controller.publish_warm_job(operation_id, selected, stage, attempt_id, 60, self.now + 120)
        self.storage.objects["/mailbox"] = warm.encode(controller.warm_command(operation_id))
        return attempt_id, selected

    def args(self, operation_id):
        return argparse.Namespace(operation_id=operation_id, session_id=session()["session_id"],
                                  session_key=session()["session_key"], mailbox_url=session()["mailbox_url"],
                                  finished_manifest_put_url=session()["finished_manifest_put_url"],
                                  deadline_unix=4600, runtime_limit_seconds=3600, poll_interval_seconds=1,
                                  state_dir=str(self.root / "pod"))

    def pod(self, operation_id, execute=None, native=None):
        def native_execute(args, directory, timeout):
            stage = next(stage for stage, path in job.BINARIES.items() if path == args[0])
            return successful_native(stage, self.seen)(args, directory, timeout)
        return warm_worker.WarmWorker(self.args(operation_id), self.storage, clock=lambda: self.now,
                                      release_dir=self.releases, verify=lambda _: None,
                                      execute=execute or worker.execute, native=native or native_execute)

    def complete(self, operation_id, attempt_id):
        self.assertEqual(self.pod(operation_id).tick(), "completed")
        self.assertTrue(self.controller().collect(attempt_id))
        self.controller().verify_receipt(attempt_id)
        self.controller().finish_warm_job(attempt_id, "accepted")

    def test_multiple_fri_snark_jobs_reuse_one_pod_and_standard_receipts(self):
        operation_id = self.launch()
        self.assertEqual(self.launch(), operation_id)
        for number, stage in enumerate(("FRI", "SNARK", "FRI"), 1):
            attempt_id, selected = self.publish(operation_id, stage, number)
            self.complete(operation_id, attempt_id)
            self.controller().tick(operation_id)
            self.assertEqual(self.count("delete"), 0)
            self.assertEqual(self.controller().operation(attempt_id)["job"], selected)
            self.assertTrue((self.store.root / (attempt_id + ".proof")).exists())
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(len(self.seen), 3)
        op = self.controller().operation(operation_id)
        self.assertEqual(op["reserved_usd"], "2")
        self.assertEqual(op["deadline_at"], 4600)
        self.assertEqual(sum(float(v["reserved_usd"]) for v in self.store.load()["operations"].values()), 2)
        stop = self.controller().stop_session(operation_id)
        self.storage.objects["/mailbox"] = warm.encode(stop)
        self.assertEqual(self.pod(operation_id).tick(), "finished")
        self.controller().tick(operation_id)
        self.assertEqual(self.count("delete"), 1)
        self.assertEqual(self.controller().operation(operation_id)["status"], "terminated")
        self.assertNotIn(session()["session_key"], json.dumps(runpod.public_status(self.store.load())))

    def test_job_collection_cannot_advance_or_terminate_session_without_native_outcome(self):
        operation_id = self.launch()
        attempt_id, _ = self.publish(operation_id)
        self.assertEqual(self.pod(operation_id).tick(), "completed")
        self.controller().collect(attempt_id)
        self.controller().tick(operation_id)
        next_id, selected = self.prepare("SNARK", 2)
        with self.assertRaisesRegex(runpod.Error, "previous_job_not_returned"):
            self.controller().publish_warm_job(operation_id, selected, "SNARK", next_id)
        with self.assertRaisesRegex(runpod.Error, "previous_job_not_returned"):
            self.controller().stop_session(operation_id)
        with self.assertRaisesRegex(runpod.Error, "cleanup_requires"):
            self.controller().terminate(operation_id)
        with self.assertRaisesRegex(runpod.Error, "terminate_warm_session_instead"):
            self.controller().terminate(attempt_id)
        self.assertEqual(self.count("delete"), 0)

    def test_attempt_is_durable_and_idempotent_but_cannot_change_manifest(self):
        operation_id = self.launch()
        attempt_id, selected = self.publish(operation_id)
        before = self.controller().warm_command(operation_id)
        self.assertEqual(self.controller().publish_warm_job(operation_id, selected, "FRI", attempt_id, 60, 1120), attempt_id)
        self.assertEqual(before, self.controller().warm_command(operation_id))
        changed = {**selected, "manifest_sha256": "a" * 64}
        with self.assertRaisesRegex(runpod.Error, "warm_attempt_reused"):
            self.controller().publish_warm_job(operation_id, changed, "FRI", attempt_id, 60, 1120)
        self.assertEqual(self.count("create"), 1)

    def test_create_ambiguity_reconciles_without_second_post_or_released_budget(self):
        self.api.create_error = runpod.Error("transport_failure")
        operation_id = self.launch()
        self.api.hide_all = True
        self.controller().reconcile(operation_id)
        self.assertEqual(self.launch(), operation_id)
        with self.assertRaisesRegex(runpod.Error, "concurrency_limit"):
            self.controller().launch_session({**session(), "session_id": "7" * 32})
        self.api.hide_all = False
        self.controller().reconcile(operation_id)
        self.assertEqual(self.controller().operation(operation_id)["status"], "active")
        self.assertEqual(self.count("create"), 1)

    def test_session_intent_persists_before_provider_post_interruption(self):
        def interrupt(_):
            op = next(iter(self.store.load()["operations"].values()))
            self.assertEqual(op["kind"], "warm_session")
            self.assertEqual(op["status"], "create_uncertain")
            raise KeyboardInterrupt
        with patch.object(self.api, "create", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.launch()
        operation_id = self.launch()
        self.assertEqual(self.controller().operation(operation_id)["status"], "create_uncertain")
        self.assertEqual(self.count("create"), 0)

    def test_hard_deadline_and_unknown_provider_state_cleanup_without_job_collection(self):
        for status in (None, "PAUSED", ["RUNNING"]):
            with self.subTest(status=status):
                self.api = FakeApi()
                state = self.store.load()
                state["operations"] = {}
                self.store.save(state)
                operation_id = self.launch()
                self.api.pods["pod_1"]["status"] = status
                with patch.object(self.storage, "json", side_effect=AssertionError("no one-job collection")):
                    self.controller().tick(operation_id)
                self.assertEqual(self.count("delete"), 1)
        state = self.store.load()
        state["operations"] = {}
        self.store.save(state)
        self.api = FakeApi()
        operation_id = self.launch()
        self.now = 4600
        self.controller().tick(operation_id)
        self.assertEqual(self.count("delete"), 1)
        self.assertEqual(self.controller().operation(operation_id)["cleanup_reason"], "runtime_deadline_or_clock_rollback")

    def test_ownership_mismatch_never_deletes_warm_pod(self):
        operation_id = self.launch()
        self.api.pods["pod_1"]["env"]["ZKSYS_RENTAL_CONTROLLER_ID"] = "another"
        with self.assertRaisesRegex(runpod.Error, "ownership_mismatch"):
            self.controller().terminate(operation_id, failure=True)
        self.assertEqual(self.count("delete"), 0)

    def test_ambiguous_delete_keeps_intent_until_disappearance(self):
        operation_id = self.launch()
        self.api.delete_error = runpod.Error("transport_failure")
        with self.assertRaises(runpod.Error):
            self.controller().terminate(operation_id, failure=True)
        self.assertEqual(self.controller().operation(operation_id)["status"], "delete_uncertain")
        self.controller().tick(operation_id)
        self.assertEqual(self.controller().operation(operation_id)["status"], "terminated")
        self.assertEqual(self.count("delete"), 1)

    def test_failed_job_requires_session_cleanup_and_does_not_enable_next(self):
        operation_id = self.launch()
        attempt_id, _ = self.publish(operation_id)
        with self.assertRaisesRegex(runpod.Error, "durable_artifact_required"):
            self.controller().finish_warm_job(attempt_id, "returned")
        self.controller().finish_warm_job(attempt_id, "failed")
        self.controller().tick(operation_id)
        self.assertEqual(self.count("delete"), 1)

    def test_finished_receipt_is_authenticated_and_bound_to_exact_stop(self):
        operation_id = self.launch()
        stop = self.controller().stop_session(operation_id)
        body = {"session_id": session()["session_id"], "operation_id": operation_id, "sequence": 1,
                "command_sha256": "9" * 64, "completed_jobs": 0, "status": "finished"}
        self.storage.objects["/finished"] = warm.encode(warm.sign_finished(body, session()["session_key"]))
        with self.assertRaisesRegex(runpod.Error, "finished_receipt_mismatch"):
            self.controller().tick(operation_id)
        self.assertEqual(self.count("delete"), 0)
        body["command_sha256"] = warm.command_hash(stop)
        self.storage.objects["/finished"] = warm.encode(warm.sign_finished(body, "b" * 64))
        with self.assertRaisesRegex(runpod.Error, "authentication_failed"):
            self.controller().tick(operation_id)
        self.assertEqual(self.count("delete"), 0)

    def test_finished_cached_receipt_is_revalidated_before_normal_delete(self):
        operation_id = self.launch()
        stop = self.controller().stop_session(operation_id)
        self.storage.objects["/mailbox"] = warm.encode(stop)
        self.pod(operation_id).tick()
        self.controller().collect_session(operation_id)
        state = self.store.load()
        state["operations"][operation_id]["finished_receipt"]["mac"] = "0" * 64
        self.store.save(state)
        with self.assertRaisesRegex(runpod.Error, "authentication_failed"):
            self.controller().terminate(operation_id)
        self.assertEqual(self.count("delete"), 0)

    def test_graceful_worker_exit_collects_finished_receipt_before_delete(self):
        operation_id = self.launch()
        self.storage.objects["/mailbox"] = warm.encode(self.controller().stop_session(operation_id))
        self.pod(operation_id).tick()
        self.api.pods["pod_1"]["status"] = "EXITED"
        self.controller().tick(operation_id)
        op = self.controller().operation(operation_id)
        self.assertIsNotNone(op["finished_receipt"])
        self.assertEqual(op["status"], "terminated")
        self.assertEqual(self.count("delete"), 1)

    def test_job_and_stop_commands_never_extend_original_session_deadline(self):
        operation_id = self.launch()
        attempt_id, selected = self.prepare("FRI", 1)
        with self.assertRaisesRegex(runpod.Error, "outside_session_deadline"):
            self.controller().publish_warm_job(operation_id, selected, "FRI", attempt_id, 60, 4601)
        with self.assertRaisesRegex(runpod.Error, "outside_session_deadline"):
            self.controller().publish_warm_job(operation_id, selected, "FRI", attempt_id, 3601, 4600)
        self.now = 4600
        with self.assertRaisesRegex(runpod.Error, "deadline_elapsed"):
            self.controller().stop_session(operation_id)

    def test_capacity_counts_sessions_not_virtual_jobs_and_lifetime_reservation_persists(self):
        operation_id = self.launch()
        attempt_id, _ = self.publish(operation_id)
        self.controller().terminate(operation_id, failure=True)
        self.assertTrue(self.controller().check_session_capacity())
        self.controller().launch_session({**session(), "session_id": "7" * 32})
        self.controller().terminate(next(key for key, op in self.store.load()["operations"].items()
                                         if op.get("kind") == "warm_session" and key != operation_id), failure=True)
        with self.assertRaisesRegex(runpod.Error, "lifetime_budget_limit"):
            self.controller().check_session_capacity()
        self.assertEqual(self.controller().operation(attempt_id)["reserved_usd"], "0")

    def test_worker_never_reexecutes_completed_or_replayed_command_after_restart(self):
        operation_id = self.launch()
        self.publish(operation_id)
        self.assertEqual(self.pod(operation_id).tick(), "completed")
        self.now = 1121
        with patch.object(worker, "run_native", side_effect=AssertionError("no second compute")):
            self.assertEqual(self.pod(operation_id).tick(), "waiting")
        self.assertEqual(len(self.seen), 1)

    def test_worker_recovers_ambiguous_artifact_upload_from_exact_cached_output(self):
        operation_id = self.launch()
        attempt_id, selected = self.publish(operation_id)
        self.storage.fail_once_path = self.storage.key(selected["result_artifact_url"])
        with self.assertRaisesRegex(runpod.Error, "warm_transport_retry"):
            self.pod(operation_id).tick()
        artifact = self.storage.objects[self.storage.key(selected["result_artifact_url"])]
        self.assertEqual(self.pod(operation_id, execute=lambda *args, **kwargs: self.fail("native rerun")).tick(), "completed")
        self.assertTrue(self.controller().collect(attempt_id))
        self.assertEqual((self.store.root / (attempt_id + ".proof")).read_bytes(), artifact)
        self.assertEqual(len(self.seen), 1)

    def test_worker_recovers_ambiguous_result_upload_without_reexecuting(self):
        operation_id = self.launch()
        _, selected = self.publish(operation_id)
        self.storage.fail_once_path = self.storage.key(selected["result_manifest_url"])
        with self.assertRaisesRegex(runpod.Error, "warm_transport_retry"):
            self.pod(operation_id).tick()
        result = self.storage.objects[self.storage.key(selected["result_manifest_url"])]
        self.assertEqual(self.pod(operation_id, execute=lambda *args, **kwargs: self.fail("native rerun")).tick(), "completed")
        self.assertEqual(self.storage.objects[self.storage.key(selected["result_manifest_url"])], result)
        self.assertEqual(len(self.seen), 1)

    def test_interrupted_native_execution_fails_closed_without_reexecution(self):
        operation_id = self.launch()
        self.publish(operation_id)
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.pod(operation_id, native=interrupt).tick()
        with self.assertRaisesRegex(runpod.Error, "execution_interrupted"):
            self.pod(operation_id, execute=lambda *args, **kwargs: self.fail("native rerun")).tick()

    def test_worker_refuses_tamper_wrong_session_sequence_gap_and_expiration(self):
        operation_id = self.launch()
        self.publish(operation_id)
        original = self.controller().warm_command(operation_id)
        mutations = (("operation_id", "f" * 32), ("session_id", "e" * 32), ("expires_at", 999))
        for name, value in mutations:
            envelope = copy.deepcopy(original)
            envelope["body"][name] = value
            envelope = warm.sign_command(envelope["body"], session()["session_key"])
            self.storage.objects["/mailbox"] = warm.encode(envelope)
            with self.subTest(field=name), self.assertRaises(runpod.Error):
                self.pod(operation_id).tick()
        envelope = copy.deepcopy(original)
        envelope["mac"] = "f" * 64
        self.storage.objects["/mailbox"] = warm.encode(envelope)
        with self.assertRaisesRegex(runpod.Error, "authentication_failed"):
            self.pod(operation_id).tick()
        envelope = copy.deepcopy(original)
        envelope["body"].update(sequence=2, previous_command_sha256="f" * 64)
        self.storage.objects["/mailbox"] = warm.encode(warm.sign_command(envelope["body"], session()["session_key"]))
        with self.assertRaisesRegex(runpod.Error, "sequence_gap"):
            self.pod(operation_id).tick()
        self.assertEqual(self.seen, [])

    def test_worker_refuses_replaced_sequence_even_with_valid_session_mac(self):
        operation_id = self.launch()
        self.publish(operation_id)
        self.pod(operation_id).tick()
        envelope = copy.deepcopy(self.controller().warm_command(operation_id))
        envelope["body"]["manifest_sha256"] = "f" * 64
        self.storage.objects["/mailbox"] = warm.encode(warm.sign_command(envelope["body"], session()["session_key"]))
        with self.assertRaisesRegex(runpod.Error, "sequence_replaced"):
            self.pod(operation_id).tick()
        self.assertEqual(len(self.seen), 1)

    def test_worker_lock_prevents_concurrent_execution_and_state_reset(self):
        operation_id = self.launch()
        self.publish(operation_id)
        pod = self.pod(operation_id)
        with pod.store.lock("worker.lock"):
            with self.assertRaises(BlockingIOError):
                self.pod(operation_id)
            with self.assertRaises(BlockingIOError):
                pod.tick()
        self.assertEqual(pod.tick(), "completed")

    def test_worker_stage_is_baked_into_image_and_release_pair_must_match(self):
        operation_id = self.launch()
        self.publish(operation_id, "SNARK")
        (self.releases / "SNARK.json").unlink()
        with self.assertRaisesRegex(runpod.Error, "stage_not_in_image"):
            self.pod(operation_id).tick()
        bad = {**release("SNARK"), "app_bin_sha256": "7" * 64}
        job.write_new(self.releases / "SNARK.json", job.encode(bad))
        with self.assertRaisesRegex(runpod.Error, "release_identity_mismatch"):
            warm_worker.validate_image(self.releases, verify=lambda _: None)

    def test_worker_deadline_expires_even_with_an_empty_mailbox(self):
        operation_id = self.launch()
        pod = self.pod(operation_id)
        self.assertEqual(pod.tick(), "waiting")
        self.now = 4600
        with self.assertRaisesRegex(runpod.Error, "deadline_elapsed"):
            pod.tick()

    def test_worker_retries_transient_mailbox_and_preparing_download_in_process(self):
        operation_id = self.launch()
        attempt_id, _ = self.publish(operation_id)
        pod = self.pod(operation_id)
        original = self.storage.request
        seen_failures = set()

        def transient(url, **kwargs):
            path = self.storage.key(url)
            if (path == "/mailbox" or path.endswith("/payload")) and path not in seen_failures:
                seen_failures.add(path)
                return 503, {}, b"temporary failure"
            return original(url, **kwargs)

        def progress(_):
            self.now += 1
            if self.controller().collect(attempt_id):
                self.controller().finish_warm_job(attempt_id, "accepted")
                self.storage.objects["/mailbox"] = warm.encode(self.controller().stop_session(operation_id))

        with patch.object(self.storage, "request", side_effect=transient):
            pod.run(sleep=progress)
        self.assertEqual(len(seen_failures), 2)
        self.assertEqual(len(self.seen), 1)
        self.assertTrue(pod.state["stop"]["uploaded"])

    def test_worker_retries_ambiguous_upload_in_process_without_native_rerun(self):
        operation_id = self.launch()
        attempt_id, selected = self.publish(operation_id)
        self.storage.fail_once_path = self.storage.key(selected["result_artifact_url"])
        pod = self.pod(operation_id)
        sleeps = []

        def progress(_):
            sleeps.append(pod.state["jobs"][-1]["status"])
            self.now += 1
            if self.controller().collect(attempt_id):
                self.controller().finish_warm_job(attempt_id, "accepted")
                self.storage.objects["/mailbox"] = warm.encode(self.controller().stop_session(operation_id))

        pod.run(sleep=progress)
        self.assertIn("output_ready", sleeps)
        self.assertEqual(len(self.seen), 1)
        self.assertTrue(pod.state["stop"]["uploaded"])

    def test_worker_retries_are_bounded_by_absolute_session_deadline(self):
        operation_id = self.launch()
        args = self.args(operation_id)
        args.deadline_unix = 1003
        pod = warm_worker.WarmWorker(args, self.storage, clock=lambda: self.now, release_dir=self.releases,
                                      verify=lambda _: None, native=lambda *args: self.fail("no native work"))
        attempts = []

        def transient(*args, **kwargs):
            attempts.append(True)
            return 503, {}, b"temporary failure"

        def advance(_):
            self.now += 1

        with patch.object(self.storage, "request", side_effect=transient), self.assertRaisesRegex(
                runpod.Error, "deadline_elapsed"):
            pod.run(sleep=advance)
        self.assertEqual(len(attempts), 3)

    def test_invalid_mac_is_fatal_without_transport_retry(self):
        operation_id = self.launch()
        self.publish(operation_id)
        envelope = job.decode(self.storage.objects["/mailbox"])
        envelope["mac"] = "0" * 64
        self.storage.objects["/mailbox"] = job.encode(envelope)
        with self.assertRaisesRegex(runpod.Error, "authentication_failed"):
            self.pod(operation_id).run(sleep=lambda _: self.fail("authentication failure retried"))

    def test_script_watchdog_and_lazy_protocol_share_validation_error_type(self):
        source = Path(runpod.__file__).resolve()
        probe = ("import pathlib, sys\n"
                 "path = pathlib.Path(sys.argv[1])\n"
                 "sys.path.insert(0, str(path.parent))\n"
                 "prefix = path.read_text().rsplit('\\nif __name__ == \\\"__main__\\\":', 1)[0]\n"
                 "exec(compile(prefix, str(path), 'exec'), globals())\n"
                 "import warm_protocol\n"
                 "try:\n"
                 "    warm_protocol.validate_command({})\n"
                 "except Error:\n"
                 "    print('shared-validation-error')\n")
        result = subprocess.run([sys.executable, "-c", probe, str(source)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "shared-validation-error")


if __name__ == "__main__":
    unittest.main()
