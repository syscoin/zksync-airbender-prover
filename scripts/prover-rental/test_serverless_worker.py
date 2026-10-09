import asyncio
import base64
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse

import job
import runpod
import serverless_worker
from test_adapter import payload, release


class Storage:
    def __init__(self):
        self.objects, self.calls, self.claims = {}, [], []
        self.lock = threading.Lock()
        self.claim_mode = "normal"
        self.fail_put = None
        self.after_claim = None
        self.failures = {}
        self.put_bodies = []
        self.hide_reads = {}
        self.after_fault = None

    def fault(self, method, key):
        failures = self.failures.get((method, key), [])
        failure = failures.pop(0) if failures else None
        if failure and self.after_fault is not None:
            self.after_fault(method, key)
        if failure == "transient":
            raise serverless_worker.TransientStorageError("transient_storage_failure")
        if failure == "transport":
            raise runpod.Error("transport_failure")
        return failure

    @staticmethod
    def key(url):
        return urllib.parse.urlsplit(url).path

    def optional(self, url, maximum, deadline):
        self.calls.append(("GET", self.key(url)))
        self.fault("GET", self.key(url))
        if self.hide_reads.get(self.key(url), 0):
            self.hide_reads[self.key(url)] -= 1
            return None
        with self.lock:
            raw = self.objects.get(self.key(url))
        if raw is not None and len(raw) > maximum:
            raise runpod.Error("transport_body_too_large")
        return raw

    def get(self, url, maximum, deadline):
        raw = self.optional(url, maximum, deadline)
        if raw is None:
            raise runpod.Error("missing_object")
        return raw

    def put(self, url, data, deadline):
        key = self.key(url)
        self.calls.append(("PUT", key))
        self.put_bodies.append((key, data))
        failure = self.fault("PUT", key)
        if self.fail_put == key:
            raise runpod.Error("https://storage.example/SECRET_UPLOAD_CAPABILITY")
        with self.lock:
            self.objects[key] = data
        if failure == "lost_committed":
            raise runpod.Error("transport_failure")

    def claim(self, url, data, deadline):
        key = self.key(url)
        with self.lock:
            self.claims.append(job.decode(data))
            if self.claim_mode == "lost_uncommitted":
                raise runpod.Error("transport_failure")
            if self.claim_mode == "lost_other":
                self.objects[key] = job.encode({**job.decode(data), "claim_nonce": "f" * 64})
                raise runpod.Error("transport_failure")
            won = key not in self.objects
            if won:
                self.objects[key] = data
        if self.after_claim is not None:
            self.after_claim()
        if self.claim_mode == "lost_committed":
            raise runpod.Error("transport_failure")
        return won


class Session:
    def __init__(self, owner, *, lifetime_seconds, **_):
        self.owner = owner
        self.ready = self.closed = False
        self.block = owner.block_next
        owner.block_next = False
        self.started = threading.Event()
        self.reaped = threading.Event()
        self.close_gate = None
        self.fail_cleanup = False
        self.lifetime = lifetime_seconds
        self.deadline = time.monotonic() + lifetime_seconds
        self.wall_deadline = time.time() + lifetime_seconds
        self.compute_timeout = None

    def prewarm(self, release, timeout):
        self.owner.events.append("prewarm")
        time.sleep(self.owner.prewarm_delay)
        self.ready = True

    def usable(self, minimum_remaining_seconds=0):
        return (self.ready and not self.closed and time.monotonic() + minimum_remaining_seconds < self.deadline
                and time.time() + minimum_remaining_seconds < self.wall_deadline)

    def run(self, work, release, directory, timeout, *, deadline_unix, require_full_timeout=False):
        assert require_full_timeout
        assert self.usable(timeout)
        assert time.time() + timeout < deadline_unix
        self.compute_timeout = timeout
        if self.owner.sessions.index(self):
            assert all(session.reaped.is_set() for session in self.owner.sessions[:self.owner.sessions.index(self)])
        self.owner.computes += 1
        self.owner.events.append("compute")
        self.started.set()
        while self.block and not self.closed:
            time.sleep(.005)
        if self.closed:
            raise runpod.Error("native_stopped")
        time.sleep(self.owner.compute_delay)
        work.picked = True
        work.submit({"batch_number": work.payload["batch_number"], "vk_hash": release["vk_hash"],
                     "lease_token": work.token, "proof": base64.b64encode(b"proof" * 10).decode()})
        if self.owner.after_compute is not None:
            self.owner.after_compute()

    def close(self):
        self.closed = True
        if self.close_gate is not None:
            self.close_gate.wait(5)
        if self.fail_cleanup:
            raise runpod.Error("cleanup_failed")
        self.owner.events.append("reaped")
        self.reaped.set()


class Sessions:
    def __init__(self):
        self.sessions, self.events, self.computes = [], [], 0
        self.block_next = False
        self.prewarm_delay = 0
        self.after_compute = None
        self.compute_delay = 0

    def __call__(self, **kwargs):
        result = Session(self, **kwargs)
        self.sessions.append(result)
        return result


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release_path = self.root / "release.json"
        self.release_path.write_bytes(job.encode(release("FRI")))
        self.storage, self.sessions = Storage(), Sessions()
        self.worker = self.make_worker("state")
        self.worker.initialize()

    def make_worker(self, name):
        worker = serverless_worker.ServerlessFriWorker(
            network=self.storage, session_factory=self.sessions, release_path=self.release_path,
            verify=lambda _: None, state_dir=self.root / name)
        self.addCleanup(worker.close)
        return worker

    def request(self, number=1):
        identity = f"{number:032x}"
        prefix = f"/{identity}/"
        url = lambda name: f"https://storage.example{prefix}{name}?SCOPED_SECRET"
        raw_payload = job.encode(payload("FRI"))
        manifest = {"schema_version": 1, "job_id": "fri-12", "stage": "FRI",
                    "release_sha256": job.hash_bytes(self.release_path.read_bytes()),
                    "payload": {"url": url("payload"), "sha256": job.hash_bytes(raw_payload), "bytes": len(raw_payload)},
                    "artifact_put_url": url("artifact"), "result_manifest_put_url": url("result"), "chain_binding": None}
        raw_manifest = job.encode(manifest)
        self.storage.objects[prefix + "payload"] = raw_payload
        self.storage.objects[prefix + "manifest"] = raw_manifest
        return {"id": "provider-id", "input": {
            "schema_version": 1, "attempt_id": identity, "job_id": "fri-12", "stage": "FRI",
            "manifest_url": url("manifest"), "manifest_sha256": job.hash_bytes(raw_manifest),
            "deadline_unix": int(time.time()) + 120, "runtime_limit_seconds": 60,
            "claim_get_url": url("claim"), "claim_put_url": url("claim"),
            "artifact_get_url": url("artifact"), "result_manifest_get_url": url("result")}}

    async def failure(self, request, worker=None):
        with self.assertRaisesRegex(runpod.Error, "^serverless_job_failed$") as caught:
            await (worker or self.worker).handler(request)
        self.assertNotIn("SECRET", str(caught.exception))
        return caught.exception

    async def until(self, predicate):
        for _ in range(500):
            if predicate():
                return
            await asyncio.sleep(.005)
        self.fail("timed out waiting for worker state")

    async def test_initialize_prewarms_and_jobs_reuse_native_session_with_durable_ack(self):
        self.assertEqual(self.sessions.events, ["prewarm"])
        first = self.request()
        result = await self.worker.handler(first)
        result_key = self.storage.key(first["input"]["result_manifest_get_url"])
        self.assertEqual(job.decode(self.storage.objects[result_key]), result)
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(len(self.sessions.sessions), 1)
        self.assertEqual(await self.worker.handler(first), result)
        await self.worker.handler(self.request(2))
        self.assertEqual(self.sessions.computes, 2)
        self.assertEqual(len(self.sessions.sessions), 1)
        self.assertNotEqual(self.storage.claims[0]["claim_nonce"], self.storage.claims[1]["claim_nonce"])
        self.assertEqual(set(result), set(serverless_worker.RESULT_FIELDS))
        self.assertNotIn("url", job.encode(result).decode())
        self.assertFalse((self.worker.state_dir / first["input"]["attempt_id"]).exists())
        self.assertEqual([path.name for path in self.worker.state_dir.iterdir()], ["worker-process.lock"])

    async def test_new_worker_recovers_completed_result_without_recomputing(self):
        request = self.request()
        result = await self.worker.handler(request)
        other = self.make_worker("other")
        other.initialize()
        self.assertEqual(await other.handler(request), result)
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(len(self.storage.claims), 1)

    async def test_ambiguous_claim_put_requires_exact_invocation_nonce_readback(self):
        self.storage.claim_mode = "lost_committed"
        await self.worker.handler(self.request())
        self.assertEqual(self.sessions.computes, 1)
        for number, mode in ((2, "lost_uncommitted"), (3, "lost_other")):
            self.storage.claim_mode = mode
            await self.failure(self.request(number))
        self.assertEqual(self.sessions.computes, 1)

    async def test_started_attempt_never_recomputes_on_another_worker(self):
        self.sessions.sessions[0].block = True
        request = self.request()
        running = asyncio.create_task(self.worker.handler(request))
        await self.until(self.sessions.sessions[0].started.is_set)
        other = self.make_worker("other")
        other.initialize()
        await self.failure(request, other)
        self.assertEqual(self.sessions.computes, 1)
        running.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await running
        await self.failure(request)
        self.assertEqual(self.sessions.computes, 1)

    async def test_failed_upload_resumes_exact_stored_proof_without_compute(self):
        for number, failed_object in ((1, "artifact"), (2, "result")):
            with self.subTest(failed_object=failed_object):
                request = self.request(number)
                self.storage.fail_put = self.storage.key(request["input"][
                    "artifact_get_url" if failed_object == "artifact" else "result_manifest_get_url"])
                await self.failure(request)
                computed = self.sessions.computes
                attempt_dir = self.worker.state_dir / request["input"]["attempt_id"]
                self.assertTrue((attempt_dir / "proof.json").exists())
                self.storage.fail_put = None
                await self.worker.handler(request)
                self.assertEqual(self.sessions.computes, computed)
                self.assertFalse(attempt_dir.exists())

    async def test_another_worker_finishes_result_upload_from_durable_artifact(self):
        request = self.request()
        self.storage.fail_put = self.storage.key(request["input"]["result_manifest_get_url"])
        await self.failure(request)
        self.storage.fail_put = None
        other = self.make_worker("other")
        other.initialize()
        await other.handler(request)
        self.assertEqual(self.sessions.computes, 1)

    async def test_expired_input_refuses_before_network_or_claim(self):
        request = self.request()
        request["input"]["deadline_unix"] = int(time.time()) - 1
        await self.failure(request)
        self.assertEqual(self.storage.calls, [])
        self.assertEqual(self.storage.claims, [])
        self.assertEqual(self.sessions.computes, 0)
        self.assertFalse(self.sessions.sessions[0].closed)
        self.assertEqual(len(self.sessions.sessions), 1)

    async def test_wall_time_is_rechecked_after_claim_and_restore(self):
        request = self.request()
        clock = [time.time()]
        self.storage.after_claim = lambda: clock.__setitem__(0, request["input"]["deadline_unix"] + 1)
        with patch.object(serverless_worker.time, "time", side_effect=lambda: clock[0]):
            await self.failure(request)
        self.assertEqual(self.sessions.computes, 0)
        self.assertEqual(len(self.storage.claims), 1)
        await self.failure(request)
        self.assertEqual(self.sessions.computes, 0)

    async def test_cancel_reaps_and_joins_before_accepting_next_job_even_when_cancelled_twice(self):
        session = self.sessions.sessions[0]
        session.block = True
        session.close_gate = threading.Event()
        first = asyncio.create_task(self.worker.handler(self.request()))
        await self.until(session.started.is_set)
        first.cancel()
        await self.until(lambda: session.closed)
        second = asyncio.create_task(self.worker.handler(self.request(2)))
        first.cancel()
        await asyncio.sleep(.05)
        self.assertFalse(first.done())
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(len(self.sessions.sessions), 1)
        session.close_gate.set()
        with self.assertRaises(asyncio.CancelledError):
            await first
        await second
        self.assertTrue(session.reaped.is_set())
        self.assertEqual(self.sessions.computes, 2)

    async def test_runtime_ownership_fence_blocks_a_restarted_adapter_until_close(self):
        other = self.make_worker("state")
        with self.assertRaisesRegex(runpod.Error, "serverless_runtime_owned"):
            other.initialize()
        session = self.sessions.sessions[0]
        session.block = True
        session.close_gate = threading.Event()
        running = asyncio.create_task(self.worker.handler(self.request()))
        await self.until(session.started.is_set)
        running.cancel()
        await self.until(lambda: session.closed)
        with self.assertRaisesRegex(runpod.Error, "serverless_runtime_owned"):
            other.initialize()
        session.close_gate.set()
        with self.assertRaises(asyncio.CancelledError):
            await running
        with self.assertRaisesRegex(runpod.Error, "serverless_runtime_owned"):
            other.initialize()
        self.worker.close()
        other.initialize()
        self.assertTrue(session.reaped.is_set())

    async def test_dead_idle_session_rotates_only_after_its_cleanup(self):
        first = self.sessions.sessions[0]
        first.ready = False
        await self.worker.handler(self.request())
        self.assertTrue(first.reaped.is_set())
        self.assertEqual(len(self.sessions.sessions), 2)
        self.assertEqual(self.sessions.computes, 1)

    async def test_nearly_expired_guardian_rotates_for_both_clocks_before_compute(self):
        for number, field, now in ((1, "deadline", time.monotonic), (2, "wall_deadline", time.time)):
            with self.subTest(clock=field):
                old = self.worker.session
                setattr(old, field, now() + .5)
                await self.worker.handler(self.request(number))
                self.assertTrue(old.reaped.is_set())
                self.assertEqual(self.worker.session.compute_timeout, 60)
        self.assertEqual(self.sessions.computes, 2)

    async def test_restart_setup_has_separate_budget_from_full_proving_allowance(self):
        old = self.worker.session
        old.ready = False
        self.sessions.prewarm_delay = 1.1
        request = self.request()
        request["input"].update(runtime_limit_seconds=1, deadline_unix=int(time.time()) + 10)
        started = time.monotonic()
        await self.worker.handler(request)
        self.assertGreater(time.monotonic() - started, 1)
        self.assertTrue(old.reaped.is_set())
        self.assertEqual(self.worker.session.compute_timeout, 1)
        self.assertEqual(self.sessions.computes, 1)

    async def test_separate_setup_allowance_does_not_extend_native_proving_runtime(self):
        self.sessions.compute_delay = 1.1
        request = self.request()
        request["input"].update(runtime_limit_seconds=1, deadline_unix=int(time.time()) + 10)
        await self.failure(request)
        self.assertEqual(self.sessions.computes, 1)
        self.assertNotIn(self.storage.key(request["input"]["result_manifest_get_url"]), self.storage.objects)

    async def test_fresh_session_lifetime_covers_setup_and_runtime_above_default_lifetime(self):
        request = self.request()
        request["input"].update(runtime_limit_seconds=4000, deadline_unix=int(time.time()) + 5000)
        await self.worker.handler(request)
        self.assertGreater(self.worker.session.lifetime, 4000 + self.worker.initialization_timeout)
        self.assertEqual(self.worker.session.compute_timeout, 4000)

    async def test_insufficient_lease_and_unsupported_runtime_refuse_without_claim(self):
        request = self.request()
        request["input"]["deadline_unix"] = int(time.time()) + 30
        await self.failure(request)
        request = self.request(2)
        request["input"]["runtime_limit_seconds"] = serverless_worker.MAX_RUNTIME_SECONDS + 1
        await self.failure(request)
        self.assertEqual(self.storage.claims, [])
        self.assertEqual(self.sessions.computes, 0)

    async def test_disk_persistence_and_claim_latency_cannot_shorten_native_runtime(self):
        for number, phase in ((1, "claim"), (2, "binding")):
            with self.subTest(phase=phase):
                old = self.worker.session
                def age_guardian():
                    old.deadline = time.monotonic() + .5
                self.storage.after_claim = age_guardian if phase == "claim" else None
                write_new = job.write_new
                def slow_binding(path, data):
                    write_new(path, data)
                    if Path(path).name == "binding.json":
                        age_guardian()
                with patch.object(job, "write_new", side_effect=slow_binding if phase == "binding" else write_new):
                    await self.worker.handler(self.request(number))
                self.assertTrue(old.reaped.is_set())
                self.assertEqual(self.worker.session.compute_timeout, 60)
        self.assertEqual(self.sessions.computes, 2)
        self.assertEqual(len(self.storage.claims), 2)

    async def test_transient_publication_recovers_inside_same_handler_without_recompute(self):
        request = self.request()
        artifact = self.storage.key(request["input"]["artifact_get_url"])
        result = self.storage.key(request["input"]["result_manifest_get_url"])
        def failures():
            self.storage.failures = {("PUT", artifact): ["transient", "transport", "lost_committed"],
                                     ("PUT", result): ["lost_committed"],
                                     ("GET", artifact): ["transient"], ("GET", result): ["transport"]}
        self.sessions.after_compute = failures
        receipt = await self.worker.handler(request)
        self.assertEqual(receipt, job.decode(self.storage.objects[result]))
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(len(self.storage.claims), 1)
        artifact_puts = [body for key, body in self.storage.put_bodies if key == artifact]
        self.assertEqual(len(artifact_puts), 3)
        self.assertTrue(all(body == self.storage.objects[artifact] for body in artifact_puts))
        self.assertEqual(len([key for key, _ in self.storage.put_bodies if key == result]), 1)

    async def test_missing_readback_retries_exact_proof_without_recompute(self):
        request = self.request()
        artifact = self.storage.key(request["input"]["artifact_get_url"])
        self.sessions.after_compute = lambda: self.storage.hide_reads.update({artifact: 3})
        await self.worker.handler(request)
        self.assertEqual(self.sessions.computes, 1)
        puts = [body for key, body in self.storage.put_bodies if key == artifact]
        self.assertEqual(len(puts), 2)
        self.assertEqual(puts[0], puts[1])

    async def test_conflicting_publication_readback_fails_without_overwriting(self):
        request = self.request()
        artifact = self.storage.key(request["input"]["artifact_get_url"])
        self.sessions.after_compute = lambda: self.storage.objects.update({artifact: b"conflicting-object"})
        await self.failure(request)
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(self.storage.objects[artifact], b"conflicting-object")
        self.assertEqual([body for key, body in self.storage.put_bodies if key == artifact], [])

    async def test_cancellation_interrupts_publication_retry_wait_and_retains_exact_proof(self):
        request = self.request()
        artifact = self.storage.key(request["input"]["artifact_get_url"])
        self.sessions.after_compute = lambda: self.storage.failures.update({("PUT", artifact): ["transient"] * 100})
        with patch.object(serverless_worker, "PUBLICATION_RETRY_SECONDS", 5):
            running = asyncio.create_task(self.worker.handler(request))
            await self.until(lambda: bool(self.storage.put_bodies))
            await asyncio.sleep(.02)
            running.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(running, 1)
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(len(self.storage.put_bodies), 1)
        self.assertTrue(self.sessions.sessions[0].reaped.is_set())
        self.assertTrue((self.worker.state_dir / request["input"]["attempt_id"] / "proof.json").exists())

    async def test_publication_retry_respects_original_wall_and_monotonic_lease_deadlines(self):
        for number, clock_name in ((1, "wall"), (2, "monotonic")):
            with self.subTest(clock=clock_name):
                request = self.request(number)
                artifact = self.storage.key(request["input"]["artifact_get_url"])
                wall, mono = [time.time()], [time.monotonic()]
                clock = SimpleNamespace(time=lambda: wall[0], monotonic=lambda: mono[0])
                def after_compute():
                    self.storage.failures[("PUT", artifact)] = ["transient"]
                    def expire_after_failed_put(method, key):
                        if method == "PUT" and key == artifact:
                            if clock_name == "wall":
                                wall[0] = request["input"]["deadline_unix"] + 1
                            else:
                                mono[0] += 1000
                                wall[0] -= 1000
                    self.storage.after_fault = expire_after_failed_put
                self.sessions.after_compute = after_compute
                with patch.object(serverless_worker, "time", clock):
                    await self.failure(request)
                self.assertNotIn(artifact, self.storage.objects)
                self.assertEqual(len([key for key, _ in self.storage.put_bodies if key == artifact]), 1)
                self.assertTrue((self.worker.state_dir / request["input"]["attempt_id"] / "proof.json").exists())
        self.assertEqual(self.sessions.computes, 2)

    async def test_serverless_worker_proves_with_real_persistent_http_session(self):
        import fri_session
        from test_fri_session import FAKE
        fake = self.root / "fake-native.py"
        fake.write_text(FAKE)
        factory = lambda **kwargs: fri_session.FriSession(
            command_factory=lambda *_: [sys.executable, str(fake), str(self.root), "normal"], **kwargs)
        real_worker = serverless_worker.ServerlessFriWorker(
            network=self.storage, session_factory=factory, release_path=self.release_path, verify=lambda _: None,
            state_dir=self.root / "real-session")
        self.addCleanup(real_worker.close)
        real_worker.initialize()
        result = await real_worker.handler(self.request())
        self.assertEqual(result["job_id"], "fri-12")
        self.assertTrue(real_worker.session.usable())

    async def test_each_interrupted_cleanup_window_recovers_only_remote_completed_result(self):
        for number, window in enumerate(("proof_unlink", "binding_unlink", "directory_fsync", "rmdir", "parent_fsync"), 1):
            with self.subTest(window=window):
                request = self.request(number)
                directory = self.worker.state_dir / request["input"]["attempt_id"]
                unlink, rmdir, sync = Path.unlink, Path.rmdir, serverless_worker.sync_dir
                def interrupted_unlink(path, *args, **kwargs):
                    unlink(path, *args, **kwargs)
                    if path.parent == directory and path.name == ("proof.json" if window == "proof_unlink" else "binding.json"):
                        raise OSError("cleanup_interrupted")
                def interrupted_rmdir(path, *args, **kwargs):
                    rmdir(path, *args, **kwargs)
                    if path == directory:
                        raise OSError("cleanup_interrupted")
                def interrupted_sync(path):
                    sync(path)
                    if (Path(path) == directory if window == "directory_fsync" else
                            Path(path) == self.worker.state_dir and not directory.exists()):
                        raise OSError("cleanup_interrupted")
                patcher = (patch.object(Path, "unlink", interrupted_unlink) if window.endswith("unlink") else
                           patch.object(Path, "rmdir", interrupted_rmdir) if window == "rmdir" else
                           patch.object(serverless_worker, "sync_dir", interrupted_sync))
                with patcher:
                    await self.failure(request)
                computes = self.sessions.computes
                result = await self.worker.handler(request)
                self.assertEqual(result["operation_id"], request["input"]["attempt_id"])
                self.assertEqual(self.sessions.computes, computes)
                self.assertFalse(directory.exists())

    async def test_missing_binding_never_authorizes_compute_or_incomplete_publication(self):
        request = self.request()
        directory = self.worker.state_dir / request["input"]["attempt_id"]
        directory.mkdir(mode=0o700)
        await self.failure(request)
        self.assertEqual(self.sessions.computes, 0)
        self.assertEqual(self.storage.claims, [])
        directory.rmdir()
        await self.worker.handler(request)
        directory.mkdir(mode=0o700)
        result_key = self.storage.key(request["input"]["result_manifest_get_url"])
        result = self.storage.objects.pop(result_key)
        await self.failure(request)
        self.assertTrue(directory.exists())
        self.assertNotIn(result_key, self.storage.objects)
        self.storage.objects[result_key] = result
        await self.worker.handler(request)
        self.assertEqual(self.sessions.computes, 1)
        self.assertFalse(directory.exists())

    async def test_orphan_cleanup_rejects_changed_identity_and_unknown_files(self):
        request = self.request()
        await self.worker.handler(request)
        directory = self.worker.state_dir / request["input"]["attempt_id"]
        directory.mkdir(mode=0o700)
        original_objects = copy.deepcopy(self.storage.objects)
        for field in ("job_id", "manifest_sha256", "deadline_unix"):
            with self.subTest(field=field):
                changed = copy.deepcopy(request)
                self.storage.objects = copy.deepcopy(original_objects)
                if field == "deadline_unix":
                    changed["input"][field] += 1
                else:
                    manifest_key = self.storage.key(changed["input"]["manifest_url"])
                    manifest = job.decode(self.storage.objects[manifest_key])
                    if field == "job_id":
                        changed["input"]["job_id"] = manifest["job_id"] = "different-job"
                    else:
                        manifest["payload"]["url"] += "&refreshed=1"
                    self.storage.objects[manifest_key] = job.encode(manifest)
                    changed["input"]["manifest_sha256"] = job.hash_bytes(self.storage.objects[manifest_key])
                await self.failure(changed)
                self.assertTrue(directory.exists())
        self.storage.objects = original_objects
        unknown = directory / "unrelated-authority.json"
        unknown.write_bytes(b"do not adopt")
        os.chmod(unknown, 0o600)
        await self.failure(request)
        self.assertEqual(unknown.read_bytes(), b"do not adopt")
        self.assertEqual(self.sessions.computes, 1)

    async def test_failed_cleanup_permanently_refuses_new_compute(self):
        session = self.sessions.sessions[0]
        session.fail_cleanup = True
        request = self.request()
        self.storage.fail_put = self.storage.key(request["input"]["artifact_get_url"])
        await self.failure(request)
        self.assertTrue(self.worker.poisoned)
        await self.failure(self.request(2))
        self.assertEqual(self.sessions.computes, 1)
        session.fail_cleanup = False

    async def test_malformed_input_and_manifest_fail_before_compute_claim(self):
        for field, value in (("stage", "SNARK"), ("attempt_id", "../escape"),
                             ("manifest_url", "http://storage.example/secret"),
                             ("runtime_limit_seconds", True), ("manifest_sha256", "f" * 64)):
            with self.subTest(field=field):
                request = self.request()
                request["input"][field] = value
                await self.failure(request)
        request = self.request(2)
        request["input"]["lease_token"] = "real-upstream-token"
        await self.failure(request)
        self.assertEqual(self.storage.claims, [])
        self.assertEqual(self.sessions.computes, 0)

    async def test_corrupted_claim_result_or_proof_fail_closed(self):
        request = self.request()
        result = await self.worker.handler(request)
        snapshot = copy.deepcopy(self.storage.objects)
        for obj, corruption in (("claim", {"claim_nonce": "invalid"}),
                                ("result", {"artifact_sha256": "f" * 64}),
                                ("artifact", {"batch_number": 99})):
            with self.subTest(obj=obj):
                self.storage.objects = copy.deepcopy(snapshot)
                key = f'/{request["input"]["attempt_id"]}/{obj}'
                self.storage.objects[key] = job.encode({**job.decode(self.storage.objects[key]), **corruption})
                await self.failure(request)
        self.assertEqual(self.sessions.computes, 1)
        self.assertEqual(result["operation_id"], request["input"]["attempt_id"])


class TransportTests(unittest.TestCase):
    def test_storage_retries_only_transient_http_statuses(self):
        network = serverless_worker.ScopedNetwork()
        for status in (408, 429, 500, 503):
            with self.subTest(status=status), patch.object(network, "request", return_value=(status, {}, b"")):
                with self.assertRaises(serverless_worker.TransientStorageError):
                    network.put("https://storage.example/artifact", b"{}", time.monotonic() + 1)
                with self.assertRaises(serverless_worker.TransientStorageError):
                    network.optional("https://storage.example/artifact", 100, time.monotonic() + 1)
        for status in (301, 400, 401, 403, 409):
            with self.subTest(status=status), patch.object(network, "request", return_value=(status, {}, b"")):
                with self.assertRaises(runpod.Error) as caught:
                    network.put("https://storage.example/artifact", b"{}", time.monotonic() + 1)
                self.assertNotIsInstance(caught.exception, serverless_worker.TransientStorageError)

    def test_claim_uses_atomic_header_and_no_provider_authorization_or_proxy(self):
        class Response(io.BytesIO):
            code = 412
            def read1(self, maximum):
                return self.read(maximum)
        class Opener:
            def open(self, request, timeout):
                self.request = request
                return Response(b"")
        opener = Opener()
        with patch.object(serverless_worker.urllib.request, "build_opener", return_value=opener) as build:
            self.assertFalse(serverless_worker.ScopedNetwork().claim(
                "https://storage.example/claim?scoped", b"{}", time.monotonic() + 5))
        self.assertEqual(opener.request.get_header("If-none-match"), "*")
        self.assertIsNone(opener.request.get_header("Authorization"))
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], runpod.NoRedirect)


if __name__ == "__main__":
    unittest.main()
