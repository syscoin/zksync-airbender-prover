#!/usr/bin/env python3
"""Reuse a bounded rental pod for authenticated, sequential one-job commands."""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import job
import warm_protocol as warm
import worker
from runpod import Error, Store, atomic_json, positive_int, private_open, require, sync_dir


RELEASE_DIR = Path("/opt/zksys-rental/releases")


class RetryableTransport(Error):
    pass


class WarmTransport:
    def __init__(self, network):
        self.network = network

    def request(self, url, **kwargs):
        try:
            status, headers, raw = self.network.request(url, **kwargs)
        except Error as error:
            if str(error) in ("transport_failure", "transport_deadline"):
                raise RetryableTransport("warm_transport_retry") from None
            raise
        if status in (408, 429) or 500 <= status <= 599:
            raise RetryableTransport("warm_transport_retry")
        return status, headers, raw

    def get(self, url, maximum, deadline=None):
        status, _, raw = self.request(url, maximum=maximum, deadline=deadline)
        require(status == 200, "warm_download_failed")
        return raw

    def put(self, url, raw, deadline=None):
        status, _, _ = self.request(url, method="PUT", data=raw, maximum=job.MAX_MANIFEST, deadline=deadline)
        require(status in (200, 201, 204), "warm_upload_failed")


def validate_image(release_dir=RELEASE_DIR, verify=job.verify_image):
    releases = {}
    common = None
    for stage in ("FRI", "SNARK"):
        path = Path(release_dir) / (stage + ".json")
        if not path.exists():
            continue
        raw = job.read_file(path, job.MAX_MANIFEST)
        identity = job.release_identity(raw)
        require(identity["stage"] == stage, "warm_release_stage_mismatch")
        shared = {name: value for name, value in identity.items()
                  if name not in ("stage", "worker_sha256", "crs_sha256")}
        require(common is None or common == shared, "warm_release_identity_mismatch")
        common = shared
        verify(identity)
        releases[stage] = {"path": path, "raw": raw, "identity": identity, "sha256": job.hash_bytes(raw)}
    require(releases, "warm_release_required")
    return releases


def atomic_bytes(path, data):
    path = Path(path)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        with os.fdopen(private_open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class WarmWorker:
    def __init__(self, args, network=None, clock=time.time, monotonic=time.monotonic,
                 release_dir=RELEASE_DIR, verify=job.verify_image, execute=worker.execute, native=worker.run_native):
        warm.identity(args.operation_id)
        warm.identity(args.session_id)
        warm.key_bytes(args.session_key)
        job.https_url(args.mailbox_url)
        job.https_url(args.finished_manifest_put_url)
        positive_int(args.deadline_unix)
        positive_int(args.runtime_limit_seconds)
        require(positive_int(args.poll_interval_seconds) <= 60, "invalid_warm_poll_interval")
        self.args, self.network, self.clock, self.monotonic = args, WarmTransport(network or job.Network()), clock, monotonic
        self.verify, self.execute, self.native = verify, execute, native
        self.releases = validate_image(release_dir, verify)
        self.deadline = monotonic() + min(args.runtime_limit_seconds, max(0, args.deadline_unix - clock()))
        self.root = Path(args.state_dir)
        require(self.root.is_absolute(), "warm_state_directory_must_be_absolute")
        try:
            self.root.mkdir(mode=0o700)
            sync_dir(self.root.parent)
        except FileExistsError:
            pass
        self.store = Store(self.root)
        self.binding = {
            "operation_id": args.operation_id, "session_id": args.session_id,
            "session_key_sha256": hashlib.sha256(warm.key_bytes(args.session_key)).hexdigest(),
            "mailbox_sha256": job.hash_bytes(args.mailbox_url.encode()),
            "finished_put_sha256": job.hash_bytes(args.finished_manifest_put_url.encode()),
            "deadline_unix": args.deadline_unix, "runtime_limit_seconds": args.runtime_limit_seconds,
            "releases": {stage: release["sha256"] for stage, release in self.releases.items()},
        }
        with self.store.lock("worker.lock", blocking=False):
            state_path = self.root / "worker.json"
            if state_path.exists():
                self.load()
            else:
                self.state = {"schema_version": 1, "binding": self.binding, "jobs": [], "stop": None}
                self.save()

    def load(self):
        self.state = job.decode(job.read_file(self.root / "worker.json", 2 * 1024 * 1024, private=True))
        require(self.state.get("binding") == self.binding, "warm_worker_session_changed")
        require(self.state.get("schema_version") == 1 and isinstance(self.state.get("jobs"), list)
                and len(self.state["jobs"]) <= warm.MAX_JOBS, "invalid_warm_worker_state")

    def save(self):
        atomic_json(self.root / "worker.json", self.state)

    def remaining(self, body=None):
        remaining = min(self.deadline - self.monotonic(), self.args.deadline_unix - self.clock())
        if body is not None:
            remaining = min(remaining, body["expires_at"] - self.clock())
        require(remaining > 0, "warm_worker_deadline_elapsed")
        return remaining

    def directory(self, record):
        path = self.root / record["command"]["body"]["attempt_id"]
        try:
            path.mkdir(mode=0o700)
            sync_dir(path.parent)
        except FileExistsError:
            pass
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
                "unsafe_warm_job_directory")
        return path

    def manifest(self, record):
        body = record["command"]["body"]
        raw = job.read_file(self.directory(record) / "manifest.json", job.MAX_MANIFEST, private=True)
        require(job.hash_bytes(raw) == body["manifest_sha256"], "warm_cached_manifest_changed")
        manifest = job.decode(raw)
        release = self.releases[body["stage"]]
        worker.validate_manifest(manifest, release["identity"], release["sha256"], body["job_id"])
        return manifest

    def validate_artifact(self, record, raw):
        body = record["command"]["body"]
        proof = job.validate_payload(job.decode(raw), body["stage"], self.releases[body["stage"]]["identity"]["vk_hash"],
                                     proof=True)
        bounds = job.decode(job.read_file(self.directory(record) / "bounds.json", job.MAX_MANIFEST, private=True))
        require(all(proof.get(name) == value for name, value in bounds.items()), "warm_cached_proof_job_mismatch")

    def result(self, record, raw):
        body = record["command"]["body"]
        return {"schema_version": 1, "operation_id": body["attempt_id"], "job_id": body["job_id"],
                "manifest_sha256": body["manifest_sha256"], "artifact_sha256": job.hash_bytes(raw),
                "artifact_bytes": len(raw)}

    def resume_uploads(self, record):
        body = record["command"]["body"]
        directory = self.directory(record)
        # A durable started intent without complete output is deliberately not retried: native
        # compute may have run before interruption, and a fresh attempt needs controller authority.
        require((directory / "artifact.json").exists(), "warm_execution_interrupted")
        raw = job.read_file(directory / "artifact.json", job.MAX_SUBMIT, private=True)
        self.validate_artifact(record, raw)
        if "artifact_sha256" in record:
            require(job.hash_bytes(raw) == record["artifact_sha256"] and len(raw) == record["artifact_bytes"],
                    "warm_cached_artifact_changed")
        result = self.result(record, raw)
        manifest = self.manifest(record)
        if (directory / "result.json").exists():
            require(job.read_file(directory / "result.json", job.MAX_MANIFEST, private=True) == job.encode(result),
                    "warm_cached_result_changed")
        else:
            atomic_bytes(directory / "result.json", job.encode(result))
        record.update(status="publishing", artifact_sha256=result["artifact_sha256"], artifact_bytes=len(raw))
        self.save()
        deadline = self.monotonic() + self.remaining(body)
        self.network.put(manifest["artifact_put_url"], raw, deadline)
        self.network.put(manifest["result_manifest_put_url"], job.encode(result), deadline)
        record["status"] = "done"
        self.save()

    def finish(self):
        stop = self.state["stop"]
        require(stop is not None, "warm_stop_required")
        self.remaining(stop["command"]["body"])
        self.network.put(self.args.finished_manifest_put_url, job.encode(stop["receipt"]), self.deadline)
        stop["uploaded"] = True
        self.save()
        return "finished"

    def tick(self):
        with self.store.lock("worker.lock", blocking=False):
            self.load()
            return self._tick()

    def _tick(self):
        self.remaining()
        if self.state["stop"] is not None:
            return self.finish()
        if self.state["jobs"] and self.state["jobs"][-1]["status"] != "done":
            record = self.state["jobs"][-1]
            if record["status"] == "preparing":
                self.execute_record(record)
            else:
                self.resume_uploads(record)
            return "completed"
        status, _, raw = self.network.request(self.args.mailbox_url, maximum=warm.MAX_MESSAGE_BYTES,
                                              deadline=min(self.deadline, self.monotonic() + 30))
        if status in (404, 204):
            return "waiting"
        require(status == 200, "warm_mailbox_download_failed")
        envelope = job.decode(raw)
        body = warm.verify_command(envelope, self.args.session_key)
        require(body["operation_id"] == self.args.operation_id and body["session_id"] == self.args.session_id,
                "warm_command_session_mismatch")
        digest = warm.command_hash(envelope)
        if body["sequence"] <= len(self.state["jobs"]):
            prior = self.state["jobs"][body["sequence"] - 1]
            require(warm.command_hash(prior["command"]) == digest, "warm_sequence_replaced")
            return "waiting"
        require(body["sequence"] == len(self.state["jobs"]) + 1, "warm_sequence_gap")
        previous = warm.command_hash(self.state["jobs"][-1]["command"]) if self.state["jobs"] else None
        require(body["previous_command_sha256"] == previous, "warm_previous_command_mismatch")
        require(body["expires_at"] <= self.args.deadline_unix, "warm_command_exceeds_session_deadline")
        remaining = self.remaining(body)
        if body["kind"] == "stop":
            receipt = warm.sign_finished({"session_id": self.args.session_id, "operation_id": self.args.operation_id,
                                          "sequence": body["sequence"], "command_sha256": digest,
                                          "completed_jobs": len(self.state["jobs"]), "status": "finished"},
                                         self.args.session_key)
            self.state["stop"] = {"command": envelope, "receipt": receipt, "uploaded": False}
            self.save()
            return self.finish()
        require(body["stage"] in self.releases, "warm_stage_not_in_image")
        require(all(record["command"]["body"]["attempt_id"] != body["attempt_id"]
                    for record in self.state["jobs"]), "warm_attempt_reused")
        record = {"command": envelope, "status": "preparing"}
        require(int(remaining) > 0, "warm_worker_deadline_elapsed")
        self.state["jobs"].append(record)
        self.save()
        self.execute_record(record)
        return "completed"

    def execute_record(self, record):
        body = record["command"]["body"]
        remaining = self.remaining(body)
        require(int(remaining) > 0, "warm_worker_deadline_elapsed")
        args = SimpleNamespace(operation_id=body["attempt_id"], job_id=body["job_id"],
                               manifest_url=body["manifest_url"], manifest_sha256=body["manifest_sha256"],
                               runtime_limit_seconds=min(body["runtime_limit_seconds"], int(remaining)))
        def start_native(command, directory, timeout):
            require(record["status"] == "preparing", "warm_compute_already_started")
            record["status"] = "executing"
            self.save()
            self.native(command, directory, min(timeout, self.remaining(body)))

        self.execute(args, network=RecordingNetwork(self, record), release_path=self.releases[body["stage"]]["path"],
                     verify=self.verify, native=start_native)
        require(record["status"] == "done", "warm_worker_result_not_durable")

    def run(self, sleep=time.sleep):
        while True:
            try:
                if self.tick() == "finished":
                    return
            except RetryableTransport:
                # The current phase determines whether retrying can download, upload, or must
                # fail closed. Neither a failed transfer nor a repeated mailbox reruns native work.
                pass
            sleep(min(self.args.poll_interval_seconds, self.remaining()))


class RecordingNetwork:
    """Persist exact native output before either remote PUT can become ambiguous."""

    def __init__(self, owner, record):
        self.owner, self.record = owner, record

    def get(self, url, maximum, deadline=None):
        owner, record = self.owner, self.record
        body = record["command"]["body"]
        raw = owner.network.get(url, maximum, min(deadline or owner.deadline, owner.deadline))
        directory = owner.directory(record)
        if url == body["manifest_url"]:
            require(job.hash_bytes(raw) == body["manifest_sha256"], "manifest_hash_mismatch")
            manifest = job.decode(raw)
            release = owner.releases[body["stage"]]
            worker.validate_manifest(manifest, release["identity"], release["sha256"], body["job_id"])
            atomic_bytes(directory / "manifest.json", raw)
        else:
            manifest = owner.manifest(record)
            require(url == manifest["payload"]["url"] and len(raw) == manifest["payload"]["bytes"]
                    and job.hash_bytes(raw) == manifest["payload"]["sha256"], "warm_payload_mismatch")
            payload = job.validate_payload(job.decode(raw), body["stage"], owner.releases[body["stage"]]["identity"]["vk_hash"])
            bounds = {name: payload[name] for name in ("batch_number", "from_batch_number", "to_batch_number", "vk_hash")
                      if name in payload}
            atomic_bytes(directory / "bounds.json", job.encode(bounds))
        return raw

    def put(self, url, raw, deadline=None):
        owner, record = self.owner, self.record
        directory = owner.directory(record)
        manifest = owner.manifest(record)
        if url == manifest["artifact_put_url"]:
            owner.validate_artifact(record, raw)
            atomic_bytes(directory / "artifact.json", raw)
            record.update(status="output_ready", artifact_sha256=job.hash_bytes(raw), artifact_bytes=len(raw))
        elif url == manifest["result_manifest_put_url"]:
            artifact = job.read_file(directory / "artifact.json", job.MAX_SUBMIT, private=True)
            require(raw == job.encode(owner.result(record, artifact)), "warm_result_mismatch")
            atomic_bytes(directory / "result.json", raw)
            record["status"] = "publishing"
        else:
            raise Error("warm_unexpected_upload")
        owner.save()
        owner.network.put(url, raw, min(deadline or owner.deadline, owner.deadline))
        if url == manifest["result_manifest_put_url"]:
            record["status"] = "done"
            owner.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-image", action="store_true")
    parser.add_argument("--operation-id")
    parser.add_argument("--session-id")
    parser.add_argument("--mailbox-url")
    parser.add_argument("--finished-manifest-put-url")
    parser.add_argument("--session-key")
    parser.add_argument("--deadline-unix", type=int)
    parser.add_argument("--runtime-limit-seconds", type=int)
    parser.add_argument("--poll-interval-seconds", type=int)
    parser.add_argument("--state-dir", default="/var/lib/zksys-warm")
    args = parser.parse_args()
    if args.validate_image:
        validate_image()
    else:
        WarmWorker(args).run()


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, Error) else "warm_worker_failed", file=sys.stderr)
        sys.exit(1)
