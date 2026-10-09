"""Persistent FRI compute behind a serial, cancellable Runpod Serverless handler."""

import asyncio
import fcntl
import http.client
import io
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
import urllib.error
import urllib.request

import fri_session
import job
from runpod import Error, NoRedirect, exact_fields, https_url, positive_int, private_open, require, sha256, sync_dir
import worker


INPUT_FIELDS = ("schema_version", "attempt_id", "job_id", "stage", "manifest_url", "manifest_sha256",
                "deadline_unix", "runtime_limit_seconds", "claim_get_url", "claim_put_url",
                "artifact_get_url", "result_manifest_get_url")
CLAIM_FIELDS = ("schema_version", "attempt_id", "job_id", "manifest_sha256", "claim_nonce", "deadline_unix")
RESULT_FIELDS = ("schema_version", "operation_id", "job_id", "manifest_sha256", "artifact_sha256", "artifact_bytes")


def validate_input(value):
    exact_fields(value, INPUT_FIELDS)
    require(value["schema_version"] == 1 and value["stage"] == "FRI", "invalid_serverless_stage")
    require(isinstance(value["attempt_id"], str) and re.fullmatch(r"[0-9a-f]{32}", value["attempt_id"]),
            "invalid_attempt_id")
    require(isinstance(value["job_id"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["job_id"]),
            "invalid_job_id")
    sha256(value["manifest_sha256"])
    positive_int(value["deadline_unix"])
    positive_int(value["runtime_limit_seconds"])
    for name in INPUT_FIELDS:
        if name.endswith("_url"):
            https_url(value[name])
    require(len(job.encode(value)) <= job.MAX_MANIFEST, "serverless_input_too_large")
    return value.copy()


class ScopedNetwork(job.Network):
    def optional(self, url, maximum, deadline):
        status, _, body = self.request(url, maximum=maximum, deadline=deadline)
        require(status in (200, 404), "scoped_download_failed")
        return body if status == 200 else None

    def claim(self, url, data, deadline):
        # The trusted controller signs this header into the attempt-scoped PUT.
        # A normal unconditional upload cannot serve as a distributed claim.
        https_url(url)
        request = urllib.request.Request(url, data=data, method="PUT", headers={
            "Accept-Encoding": "identity", "Content-Type": "application/json", "If-None-Match": "*"})
        require(time.monotonic() < deadline, "transport_deadline")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            try:
                response = opener.open(request, timeout=min(600, max(1, deadline - time.monotonic())))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                output = io.BytesIO()
                while True:
                    require(time.monotonic() < deadline, "transport_deadline")
                    part = response.read1(min(64 * 1024, job.MAX_MANIFEST - output.tell() + 1))
                    if not part:
                        require(response.code in (200, 201, 204, 412), "claim_upload_failed")
                        return response.code != 412
                    require(output.tell() + len(part) <= job.MAX_MANIFEST, "transport_body_too_large")
                    output.write(part)
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            raise Error("transport_failure") from None


def _private_directory(path):
    try:
        path.mkdir(mode=0o700)
        sync_dir(path.parent)
    except FileExistsError:
        pass
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
            "unsafe_serverless_state_directory")


class ServerlessFriWorker:
    def __init__(self, *, network=None, session_factory=None, release_path=job.RELEASE_PATH,
                 verify=job.verify_image, state_dir="/tmp/zksys-serverless-fri",
                 initialization_timeout_seconds=600, session_lifetime_seconds=3600):
        self.network = network or ScopedNetwork()
        self.session_factory = session_factory or fri_session.FriSession
        self.release_path, self.verify = release_path, verify
        self.state_dir = Path(state_dir)
        self.initialization_timeout = positive_int(initialization_timeout_seconds)
        self.session_lifetime = positive_int(session_lifetime_seconds)
        self.release = self.release_hash = self.session = None
        self.runtime_lock = None
        self.closed = self.poisoned = False
        self._handler_lock = asyncio.Lock()

    def initialize(self):
        """Run before SDK start so FlashBoot sees initialized native GPU state."""
        require(not self.closed and not self.poisoned, "serverless_worker_unavailable")
        if self.release is None:
            raw = job.read_file(self.release_path, job.MAX_MANIFEST)
            release = job.release_identity(raw)
            require(release["stage"] == "FRI", "serverless_requires_fri")
            self.verify(release)
            _private_directory(self.state_dir)
            runtime_lock = private_open(self.state_dir / "worker-process.lock", os.O_RDWR | os.O_CREAT)
            try:
                fcntl.flock(runtime_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BaseException:
                os.close(runtime_lock)
                raise Error("serverless_runtime_owned") from None
            self.runtime_lock = runtime_lock
            self.release, self.release_hash = release, job.hash_bytes(raw)
        self._ensure_session(self.initialization_timeout)

    def _retire_session(self):
        current = self.session
        if current is not None:
            try:
                current.close()
            except BaseException:
                self.poisoned = True
                raise Error("serverless_cleanup_incomplete") from None
            if self.session is current:
                self.session = None

    def close(self):
        self.closed = True
        self._retire_session()
        if self.runtime_lock is not None:
            # Closing our descriptor preserves an inherited guardian's flock;
            # explicitly unlocking it would also release that child's fence.
            os.close(self.runtime_lock)
            self.runtime_lock = None

    def _ensure_session(self, timeout, cancelled=None):
        require(not self.closed and not self.poisoned, "serverless_worker_unavailable")
        if cancelled is not None:
            require(not cancelled.is_set(), "serverless_cancelled")
        if self.session is not None and self.session.usable():
            return self.session
        self._retire_session()
        current = self.session_factory(lock_fd=self.runtime_lock, lifetime_seconds=self.session_lifetime)
        self.session = current
        try:
            require(not self.closed and not self.poisoned, "serverless_worker_unavailable")
            if cancelled is not None:
                require(not cancelled.is_set(), "serverless_cancelled")
            current.prewarm(self.release, min(timeout, self.initialization_timeout))
            require(current.usable(), "serverless_native_not_ready")
            return current
        except BaseException:
            self._retire_session()
            raise

    @staticmethod
    async def _finish(task):
        # Repeated provider cancellation must not abandon cleanup or its compute
        # thread and allow the next request to overlap an unreaped process.
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        return task.result()

    async def handler(self, provider_job):
        async with self._handler_lock:
            cancelled = threading.Event()
            native_active = threading.Event()
            task = asyncio.create_task(asyncio.to_thread(self._invoke, provider_job, cancelled, native_active))
            try:
                result = await asyncio.shield(task)
                require(result is not None, "serverless_job_failed")
                return result
            except BaseException as error:
                cancelled.set()
                cleanup_failed = False
                if native_active.is_set():
                    cleanup = asyncio.create_task(asyncio.to_thread(self._cleanup))
                    cleanup_failed = not await self._finish(cleanup)
                try:
                    await self._finish(task)
                except BaseException:
                    pass
                if cleanup_failed:
                    self.poisoned = True
                if isinstance(error, asyncio.CancelledError):
                    raise
                raise Error("serverless_job_failed") from None

    def _cleanup(self):
        try:
            self._retire_session()
            return True
        except BaseException:
            return False

    def _invoke(self, provider_job, cancelled, native_active):
        try:
            return self._execute(provider_job, cancelled, native_active)
        except BaseException:
            # An exception in a shielded task can be logged by asyncio after
            # cancellation, before its owner joins it. Keep raw storage errors
            # and capability URLs out of both provider results and that log.
            return None

    def _execute(self, provider_job, cancelled, native_active):
        require(isinstance(provider_job, dict) and "input" in provider_job, "missing_serverless_input")
        value = validate_input(provider_job["input"])
        # This nonce is deliberately created per delivery, after any snapshot
        # restoration. A nonce captured in an initialized image could be reused
        # by two workers and defeat reconciliation of an ambiguous claim PUT.
        nonce = secrets.token_hex(32)
        wall_deadline = min(value["deadline_unix"], time.time() + value["runtime_limit_seconds"])
        monotonic_deadline = time.monotonic() + value["runtime_limit_seconds"]

        def check():
            require(not self.closed and not self.poisoned and not cancelled.is_set(), "serverless_cancelled")
            require(time.time() < wall_deadline and time.monotonic() < monotonic_deadline,
                    "serverless_deadline")

        def deadline():
            check()
            return min(monotonic_deadline, time.monotonic() + wall_deadline - time.time())

        def optional(url, maximum):
            result = self.network.optional(url, maximum, deadline())
            check()
            return result

        check()
        require(self.release is not None, "serverless_worker_not_initialized")
        raw = self.network.get(value["manifest_url"], job.MAX_MANIFEST, deadline())
        check()
        require(job.hash_bytes(raw) == value["manifest_sha256"], "manifest_hash_mismatch")
        manifest = job.decode(raw)
        worker.validate_manifest(manifest, self.release, self.release_hash, value["job_id"])
        raw_payload = self.network.get(manifest["payload"]["url"], manifest["payload"]["bytes"], deadline())
        check()
        require(len(raw_payload) == manifest["payload"]["bytes"]
                and job.hash_bytes(raw_payload) == manifest["payload"]["sha256"], "input_hash_or_size_mismatch")
        payload = job.validate_payload(job.decode(raw_payload), "FRI", self.release["vk_hash"])
        directory = self.state_dir / value["attempt_id"]
        binding = {"attempt_id": value["attempt_id"], "job_id": value["job_id"],
                   "manifest_sha256": value["manifest_sha256"], "deadline_unix": value["deadline_unix"]}
        binding_path, proof_path = directory / "binding.json", directory / "proof.json"
        if directory.exists():
            _private_directory(directory)
            require(job.read_file(binding_path, job.MAX_MANIFEST, private=True) == job.encode(binding),
                    "local_attempt_mismatch")

        def complete(result):
            # Remote readback is the recovery authority after acknowledgment;
            # keeping every successful witness would fill a long-lived image.
            if directory.exists():
                for path in (proof_path, binding_path):
                    if path.exists():
                        path.unlink()
                sync_dir(directory)
                directory.rmdir()
                sync_dir(self.state_dir)
            return result

        def validate_claim(raw_claim):
            claim = job.decode(raw_claim)
            exact_fields(claim, CLAIM_FIELDS)
            require(claim["schema_version"] == 1 and all(claim[key] == field for key, field in binding.items()),
                    "claim_identity_mismatch")
            sha256(claim["claim_nonce"])
            return claim

        def validate_proof(proof):
            decoded = job.validate_payload(job.decode(proof), "FRI", self.release["vk_hash"], proof=True)
            require(decoded["batch_number"] == payload["batch_number"], "submission_job_mismatch")
            require(job.encode(decoded) == proof, "noncanonical_stored_proof")
            return proof

        def receipt(proof):
            return {"schema_version": 1, "operation_id": value["attempt_id"], "job_id": value["job_id"],
                    "manifest_sha256": value["manifest_sha256"], "artifact_sha256": job.hash_bytes(proof),
                    "artifact_bytes": len(proof)}

        def publish(proof, artifact_present=False):
            validate_proof(proof)
            if not artifact_present:
                self.network.put(manifest["artifact_put_url"], proof, deadline())
            require(optional(value["artifact_get_url"], job.MAX_SUBMIT) == proof, "artifact_readback_mismatch")
            result = receipt(proof)
            self.network.put(manifest["result_manifest_put_url"], job.encode(result), deadline())
            require(optional(value["result_manifest_get_url"], job.MAX_MANIFEST) == job.encode(result),
                    "result_readback_mismatch")
            check()
            return complete(result)

        def recover(raw_claim):
            raw_result = optional(value["result_manifest_get_url"], job.MAX_MANIFEST)
            artifact = optional(value["artifact_get_url"], job.MAX_SUBMIT)
            local = job.read_file(proof_path, job.MAX_SUBMIT, private=True) if proof_path.exists() else None
            if raw_result is not None or artifact is not None or local is not None:
                require(raw_claim is not None, "proof_without_compute_claim")
                validate_claim(raw_claim)
                if local is not None:
                    validate_proof(local)
                if artifact is not None:
                    validate_proof(artifact)
                    require(local is None or local == artifact, "conflicting_stored_proof")
                if raw_result is not None:
                    result = job.decode(raw_result)
                    exact_fields(result, RESULT_FIELDS)
                    require(artifact is not None and result == receipt(artifact), "invalid_stored_result")
                    return complete(result)
                return publish(artifact if artifact is not None else local, artifact is not None)
            return None

        raw_claim = optional(value["claim_get_url"], job.MAX_MANIFEST)
        if raw_claim is not None:
            validate_claim(raw_claim)
        recovered = recover(raw_claim)
        if recovered is not None:
            return recovered
        require(raw_claim is None, "attempt_already_started")
        native_active.set()
        current = self._ensure_session(max(.01, deadline() - time.monotonic()), cancelled)
        check()
        claim = {"schema_version": 1, **binding, "claim_nonce": nonce}
        try:
            self.network.claim(value["claim_put_url"], job.encode(claim), deadline())
        except Error:
            # A transport error says nothing about whether storage committed the
            # write. Only readback of this invocation's nonce permits compute.
            pass
        raw_claim = optional(value["claim_get_url"], job.MAX_MANIFEST)
        require(raw_claim is not None, "claim_outcome_unknown")
        stored = validate_claim(raw_claim)
        if stored["claim_nonce"] != nonce:
            recovered = recover(raw_claim)
            require(recovered is not None, "attempt_already_started")
            return recovered
        check()
        _private_directory(directory)
        job.write_new(binding_path, job.encode(binding))
        work = worker.OneJob(payload, self.release, proof_path)
        work.on_result = lambda _: check()
        current.run(work, self.release, directory, max(.01, deadline() - time.monotonic()),
                    deadline_unix=wall_deadline)
        check()
        require(work.result is not None, "native_worker_did_not_return_proof")
        return publish(work.result)
