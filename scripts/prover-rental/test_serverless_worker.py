import asyncio
import base64
import copy
import io
from pathlib import Path
import tempfile
import threading
import time
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

    @staticmethod
    def key(url):
        return urllib.parse.urlsplit(url).path

    def optional(self, url, maximum, deadline):
        self.calls.append(("GET", self.key(url)))
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
        if self.fail_put == key:
            raise runpod.Error("https://storage.example/SECRET_UPLOAD_CAPABILITY")
        with self.lock:
            self.objects[key] = data

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
    def __init__(self, owner, **_):
        self.owner = owner
        self.ready = self.closed = False
        self.block = owner.block_next
        owner.block_next = False
        self.started = threading.Event()
        self.reaped = threading.Event()
        self.close_gate = None
        self.fail_cleanup = False

    def prewarm(self, release, timeout):
        self.owner.events.append("prewarm")
        self.ready = True

    def usable(self):
        return self.ready and not self.closed

    def run(self, work, release, directory, timeout, *, deadline_unix):
        if self.owner.sessions.index(self):
            assert all(session.reaped.is_set() for session in self.owner.sessions[:self.owner.sessions.index(self)])
        self.owner.computes += 1
        self.owner.events.append("compute")
        self.started.set()
        while self.block and not self.closed:
            time.sleep(.005)
        if self.closed:
            raise runpod.Error("native_stopped")
        work.picked = True
        work.submit({"batch_number": work.payload["batch_number"], "vk_hash": release["vk_hash"],
                     "lease_token": work.token, "proof": base64.b64encode(b"proof" * 10).decode()})

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
