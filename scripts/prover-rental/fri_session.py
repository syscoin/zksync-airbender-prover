#!/usr/bin/env python3
"""SYSCOIN: Keep one native FRI process alive across authenticated rental jobs."""

import base64
import ctypes
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

import job
from runpod import Error, require
import worker
from warm_protocol import MAX_JOBS


def persistent_command(release, endpoint, directory):
    args = worker.command(release, endpoint, directory)
    for option in ("--iterations", "--sequencer-urls"):
        index = args.index(option)
        del args[index:index + 2]
    args[args.index("--prover-name") + 1] = "rental-warm-fri"
    return args


def _adopted_children():
    parent = os.getpid()
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            stat = (path / "stat").read_bytes()
            # comm can itself contain spaces, parentheses, and newlines. The fields
            # following its final closing parenthesis begin with state and PPid.
            _, separator, fields = stat.rpartition(b")")
            if not separator:
                continue
            if int(fields.split()[1]) == parent:
                yield int(path.name)
        except (OSError, ValueError, IndexError):
            # Unreadable foreign processes must not hide accessible children.
            # The caller retries discovery until waitpid independently proves ECHILD.
            continue


def _reap_adopted_children():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            time.sleep(.01)
            continue
        if pid:
            continue
        try:
            for pid in _adopted_children():
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        except (OSError, ValueError, IndexError):
            # Optional /proc task children files are not available on every
            # kernel. Even standard procfs discovery can fail temporarily; only
            # ECHILD proves it is safe to release the inherited runtime lock.
            pass
        time.sleep(.01)


def _guard(lifeline, ready, lifetime, args):
    # This separate interpreter can safely establish process supervision without
    # running a Python preexec_fn after the HTTP server has created threads.
    linux = sys.platform.startswith("linux")
    if linux:
        require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
                "fri_guardian_subreaper_failed")
    child = None
    try:
        child = subprocess.Popen(args, start_new_session=True, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.write(ready, json.dumps({"pid": child.pid}).encode() + b"\n")
        os.close(ready)
        ready = None
        deadline = time.monotonic() + lifetime
        # A restored snapshot may retain an old monotonic clock. Absolute time
        # still bounds the child even while its adapter has no active handler.
        wall_deadline = float(os.environ.get("ZKSYS_FRI_GUARD_DEADLINE_UNIX", time.time() + lifetime))
        startup_wall_deadline = float(os.environ.get("ZKSYS_FRI_GUARD_STARTUP_DEADLINE_UNIX", wall_deadline))
        startup_deadline = time.monotonic() + max(0, startup_wall_deadline - time.time())
        initialized = False
        while (child.poll() is None and time.monotonic() < deadline and time.time() < wall_deadline
               and (initialized or (time.monotonic() < startup_deadline and time.time() < startup_wall_deadline))):
            remaining = min(deadline - time.monotonic(), wall_deadline - time.time())
            if not initialized:
                remaining = min(remaining, startup_deadline - time.monotonic(), startup_wall_deadline - time.time())
            readable, _, _ = select.select([lifeline], [], [], min(.1, max(0, remaining)))
            if readable:
                marker = os.read(lifeline, 1)
                if not marker:
                    break
                if marker == b"R":
                    initialized = True
    finally:
        if ready is not None:
            os.close(ready)
        if child is not None:
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            finally:
                if linux:
                    # A subreaper also owns descendants that changed process groups.
                    _reap_adopted_children()


class FriSession:
    def __init__(self, *, lock_fd=None, lifetime_seconds=3600, command_factory=None):
        require(lifetime_seconds > 0, "fri_session_deadline")
        self.lock_fd = lock_fd
        self.deadline = time.monotonic() + lifetime_seconds
        self.wall_deadline = time.time() + lifetime_seconds
        self.command_factory = command_factory or persistent_command
        self.condition = threading.Condition()
        self.cleanup_lock = threading.Lock()
        self.current = None
        self.completed = {}
        self.release = None
        self.closed = False
        self.server = self.thread = self.process = self.temporary = None
        self.lifeline = None
        self.native_pid = None
        self.endpoint = None
        self.ready = False
        self.authorization = "Basic " + base64.b64encode(
            ("warm-fri:" + secrets.token_hex(32)).encode()).decode()

    def _serve(self):
        session = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body=b"", disposition=None):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                if disposition:
                    self.send_header("x-syscoin-prover-disposition", disposition)
                elif status == 204:
                    self.send_header("x-syscoin-prover-pick-outcome", "unleased")
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                self.connection.settimeout(10)
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied, session.authorization):
                    self.reply(401)
                    return False
                return True

            def do_GET(self):
                if self.authenticated():
                    self.reply(200, b"[]") if self.path == "/prover-jobs/v1/status/fri" else self.reply(404)

            def do_POST(self):
                if not self.authenticated():
                    return
                route = urllib.parse.urlsplit(self.path)
                try:
                    if route.path == "/prover-jobs/v1/FRI/pick":
                        with session.condition:
                            query = urllib.parse.parse_qs(route.query)
                            require(session.release["vk_hash"] in query.get("supported_vk_hashes", [""])[0].split(","),
                                    "worker_vk_advertisement_mismatch")
                            require(int(query.get("max_fri_pick_response_bytes", [0])[0]) > 0,
                                    "worker_response_capacity_too_small")
                            # Native setup and the application gate finish before
                            # the first pick. Process creation alone is not ready.
                            if not session.ready and not session.closed:
                                if session.lifeline is not None:
                                    os.write(session.lifeline, b"R")
                                session.ready = True
                                session.condition.notify_all()
                            work = session.current
                            if work is None or session.closed:
                                self.reply(204)
                            elif work.result is not None:
                                # The native client retires and fsyncs its durable
                                # submission before it can issue this next pick.
                                # Consume that request without giving it a new job.
                                session.completed[work.token] = (job.hash_bytes(work.result), len(work.result))
                                try:
                                    self.reply(204)
                                finally:
                                    session.current = None
                                    session.condition.notify_all()
                            elif work.picked:
                                self.reply(204)
                            else:
                                payload = job.encode({**work.payload, "lease_token": work.token})
                                require(len(payload) <= int(query.get("max_fri_pick_response_bytes", [0])[0]),
                                        "worker_response_capacity_too_small")
                                work.picked = True
                                self.reply(200, payload)
                    elif route.path == "/prover-jobs/v1/FRI/submit":
                        require(self.headers.get("Transfer-Encoding") is None, "chunked_submit_unsupported")
                        length = int(self.headers.get("Content-Length", "0"))
                        require(0 < length <= job.MAX_SUBMIT, "invalid_submit_size")
                        body = self.rfile.read(length)
                        require(len(body) == length, "short_submit_body")
                        value = job.decode(body)
                        require(isinstance(value, dict) and isinstance(value.get("lease_token"), str),
                                "wrong_local_token")
                        with session.condition:
                            receipt = session.completed.get(value["lease_token"])
                            if receipt is not None:
                                proof = job.encode({key: field for key, field in value.items() if key != "lease_token"})
                                require(receipt == (job.hash_bytes(proof), len(proof)), "conflicting_local_submission")
                            else:
                                require(session.current is not None and not session.closed, "wrong_local_token")
                                session.current.submit(value)
                        self.reply(204, disposition="accepted")
                    else:
                        self.reply(404)
                except (Error, OSError, ValueError):
                    self.reply(422, disposition="rejected")

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _start(self, release, timeout):
        with self.cleanup_lock:
            require(not self.closed, "fri_session_unavailable")
            self._start_locked(release, timeout)

    def _start_locked(self, release, timeout):
        self.release = release.copy()
        self.temporary = tempfile.TemporaryDirectory(prefix="zksys-warm-fri-")
        directory = Path(self.temporary.name)
        self._serve()
        args = self.command_factory(release, self.endpoint, directory)
        env = worker.native_environment()
        credentials = base64.b64decode(self.authorization[6:]).decode()
        env["ZKSYNC_SEQUENCER_URLS"] = self.endpoint.replace("http://", "http://" + credentials + "@", 1)
        env["ZKSYS_FRI_GUARD_DEADLINE_UNIX"] = str(self.wall_deadline)
        env["ZKSYS_FRI_GUARD_STARTUP_DEADLINE_UNIX"] = str(min(self.wall_deadline, time.time() + timeout))
        read_fd, self.lifeline = os.pipe()
        ready_read, ready_write = os.pipe()
        inherited = [read_fd, ready_write]
        if self.lock_fd is not None:
            inherited.append(self.lock_fd)
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--guard", str(read_fd), str(ready_write),
                 str(max(.01, self.deadline - time.monotonic())), *args], cwd=directory, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, pass_fds=tuple(inherited))
        except BaseException:
            os.close(ready_read)
            raise
        finally:
            os.close(read_fd)
            os.close(ready_write)
        try:
            ready, _, _ = select.select([ready_read], [], [], min(10, timeout))
            require(ready, "fri_native_start_timeout")
            response = os.read(ready_read, 1024)
            require(response, "fri_native_start_failed")
            self.native_pid = json.loads(response)["pid"]
        finally:
            os.close(ready_read)

    def usable(self):
        with self.condition:
            return (not self.closed and self.current is None and self.process is not None
                    and self.process.poll() is None and time.monotonic() < self.deadline
                    and time.time() < self.wall_deadline and len(self.completed) < MAX_JOBS)

    def prewarm(self, release, timeout):
        try:
            with self.condition:
                require(not self.closed and self.current is None, "fri_session_unavailable")
                require(release["stage"] == "FRI" and (self.release is None or self.release == release),
                        "fri_session_release_mismatch")
            deadline = min(self.deadline, time.monotonic() + timeout)
            wall_deadline = min(self.wall_deadline, time.time() + timeout)
            require(time.monotonic() < deadline and time.time() < wall_deadline, "fri_session_deadline")
            if self.process is None:
                self._start(release, max(.01, deadline - time.monotonic()))
            with self.condition:
                while not self.ready:
                    require(self.process.poll() is None, "fri_native_exited")
                    remaining = min(deadline - time.monotonic(), wall_deadline - time.time())
                    require(remaining > 0, "fri_session_deadline")
                    self.condition.wait(min(.05, remaining))
                require(self.process.poll() is None and time.monotonic() < deadline and time.time() < wall_deadline,
                        "fri_session_deadline")
        except BaseException:
            self.close()
            raise

    def run(self, work, release, directory, timeout, *, deadline_unix=None):
        del directory  # The native cwd and submission spool belong to the session.
        try:
            with self.condition:
                require(not self.closed and self.current is None, "fri_session_unavailable")
                require(release["stage"] == "FRI" and (self.release is None or self.release == release),
                        "fri_session_release_mismatch")
                require(len(self.completed) < MAX_JOBS, "fri_session_capacity")
                self.current = work
            deadline = min(self.deadline, time.monotonic() + timeout)
            wall_deadline = min(self.wall_deadline, time.time() + timeout,
                                deadline_unix if deadline_unix is not None else self.wall_deadline)
            require(time.monotonic() < deadline and time.time() < wall_deadline, "fri_session_deadline")
            if self.process is None:
                self._start(release, max(.01, deadline - time.monotonic()))
            with self.condition:
                while self.current is work:
                    require(self.process.poll() is None, "fri_native_exited")
                    remaining = min(deadline - time.monotonic(), wall_deadline - time.time())
                    require(remaining > 0, "fri_session_deadline")
                    self.condition.wait(min(.05, remaining))
                require(work.result is not None, "native_worker_did_not_return_proof")
        except BaseException:
            self.close()
            raise

    def close(self):
        # Cancellation and the compute thread may both initiate cleanup. They
        # must observe the same reaped guardian before a new session can start.
        with self.cleanup_lock:
            self._close()

    def _close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        if self.lifeline is not None:
            os.close(self.lifeline)
            self.lifeline = None
        if self.process is not None:
            # Never kill the guardian on timeout: it must retain the inherited
            # runtime lock while a native descendant still needs to be reaped.
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise Error("fri_native_cleanup_incomplete") from None
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.server = None
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) > 5 and sys.argv[1] == "--guard":
        _guard(int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), sys.argv[5:])
    else:
        raise SystemExit("invalid_fri_guardian_invocation")
