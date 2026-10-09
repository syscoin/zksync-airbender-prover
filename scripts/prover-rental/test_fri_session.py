import base64
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import fri_session
import job
import runpod
import worker
from test_adapter import payload, release


FAKE = r'''
import base64, json, os, pathlib, subprocess, sys, time, urllib.parse, urllib.request
root, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
url = urllib.parse.urlsplit(os.environ['ZKSYNC_SEQUENCER_URLS'])
endpoint = 'http://' + url.netloc.split('@', 1)[1]
auth = 'Basic ' + base64.b64encode((url.username + ':' + url.password).encode()).decode()
def event(kind, **extra):
    with (root / 'events').open('a') as output:
        output.write(json.dumps(dict(kind=kind, pid=os.getpid(), cwd=os.getcwd(), **extra)) + '\n')
        output.flush(); os.fsync(output.fileno())
def request(path, data=None):
    request = urllib.request.Request(endpoint + path, data=data, method='POST', headers={'Authorization':auth})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, response.read()
event('init', environment=sorted(os.environ))
if mode == 'crash': os._exit(73)
if mode in ('descendant', 'descendant_exit', 'detached', 'detached_exit'):
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'], start_new_session=mode.startswith('detached'))
    event('descendant', child=child.pid)
    if mode.endswith('_exit'): os._exit(73)
last = None
count = 0
while mode == 'hold_setup' and not (root / 'continue').exists(): time.sleep(.01)
while True:
    status, raw = request('/prover-jobs/v1/FRI/pick?supported_vk_hashes=' + '0x' + 'a1'*32 + '&max_fri_pick_response_bytes=999999')
    if status == 204:
        time.sleep(.02); continue
    value = json.loads(raw); count += 1
    event('picked', batch=value['batch_number'], token=value['lease_token'])
    if last is not None:
        assert request('/prover-jobs/v1/FRI/submit', last)[0] == 204
        event('old_retry')
    while mode == 'hold_before' and not (root / 'continue').exists(): time.sleep(.01)
    proof = {key:value for key,value in value.items() if key != 'prover_input'}
    proof['proof'] = base64.b64encode(b'p' * 41).decode()
    body = json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()
    spool = pathlib.Path('pending.json')
    with spool.open('wb') as output: output.write(body); output.flush(); os.fsync(output.fileno())
    assert request('/prover-jobs/v1/FRI/submit', body)[0] == 204
    # Treat the first response as lost: only the identical retry completes the submission.
    assert request('/prover-jobs/v1/FRI/submit', body)[0] == 204
    event('submitted', batch=value['batch_number'])
    while mode == 'hold_after' and not (root / 'continue').exists(): time.sleep(.01)
    spool.unlink()
    descriptor = os.open('.', os.O_RDONLY); os.fsync(descriptor); os.close(descriptor)
    last = body
'''


class FriSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fake = self.root / "fake.py"
        self.fake.write_text(FAKE)

    def session(self, mode="normal", **kwargs):
        session = fri_session.FriSession(command_factory=lambda *_: [sys.executable, str(self.fake), str(self.root), mode],
                                         **kwargs)
        self.addCleanup(session.close)
        return session

    def work(self, batch=12):
        return worker.OneJob({**payload("FRI"), "batch_number": batch}, release("FRI"), self.root / f"{batch}.json")

    def guardian_script(self, block_proc=False):
        guardian = self.root / "guardian.py"
        module_dir = str(Path(fri_session.__file__).parent)
        guardian.write_text(f'''import pathlib, sys
sys.path.insert(0, {module_dir!r})
import fri_session
root = pathlib.Path({str(self.root)!r})
read_text, read_bytes, iterdir = pathlib.Path.read_text, pathlib.Path.read_bytes, pathlib.Path.iterdir
def unavailable_optional(path):
    if str(path).startswith('/proc/') and path.name == 'children':
        raise FileNotFoundError('kernel_has_no_optional_children_entry')
def guarded_text(path, *args, **kwargs):
    unavailable_optional(path)
    return read_text(path, *args, **kwargs)
def guarded_bytes(path, *args, **kwargs):
    unavailable_optional(path)
    return read_bytes(path, *args, **kwargs)
def guarded_iterdir(path):
    if {block_proc!r} and str(path) == '/proc' and not (root / 'allow-proc').exists():
        (root / 'enumeration-blocked').touch()
        raise PermissionError('proc_enumeration_temporarily_unavailable')
    return iterdir(path)
pathlib.Path.read_text, pathlib.Path.read_bytes, pathlib.Path.iterdir = guarded_text, guarded_bytes, guarded_iterdir
fri_session._guard(int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), sys.argv[5:])
''')
        return guardian

    def events(self):
        path = self.root / "events"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def until(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.02)
        self.fail("timed out waiting for subprocess state")

    def run_async(self, session, work, timeout=5):
        errors = []
        def run():
            try:
                session.run(work, release("FRI"), self.root, timeout)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(thread.join, 10)
        return thread, errors

    def test_two_jobs_share_native_pid_setup_endpoint_and_spool(self):
        session = self.session()
        first, second = self.work(), self.work(13)
        callbacks = []
        first.on_result = lambda proof: callbacks.append(proof)
        session.run(first, release("FRI"), self.root, 5)
        endpoint, native_pid = session.endpoint, session.native_pid
        session.run(second, release("FRI"), self.root, 5)
        self.assertEqual((session.endpoint, session.native_pid), (endpoint, native_pid))
        events = self.events()
        self.assertEqual(len([event for event in events if event["kind"] == "init"]), 1)
        picked = [event for event in events if event["kind"] == "picked"]
        self.assertEqual([event["batch"] for event in picked], [12, 13])
        self.assertEqual(len({event["pid"] for event in picked}), 1)
        self.assertEqual(len({event["cwd"] for event in picked}), 1)
        self.assertNotEqual(picked[0]["token"], picked[1]["token"])
        self.assertEqual(len(callbacks), 1)
        self.assertIn("old_retry", [event["kind"] for event in events])
        self.assertEqual(job.decode(second.result)["batch_number"], 13)
        directory = session.temporary.name
        session.close()
        self.assertFalse(Path(directory).exists())
        self.assertIsNotNone(session.process.returncode)

    def test_result_waits_for_next_pick_and_rejects_unauthenticated_requests(self):
        session = self.session("hold_after")
        work = self.work()
        thread, errors = self.run_async(session, work)
        self.until(lambda: any(event["kind"] == "submitted" for event in self.events()))
        self.assertIsNotNone(work.result)
        self.assertTrue(thread.is_alive())
        request = urllib.request.Request(session.endpoint + "/prover-jobs/v1/FRI/pick", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 401)
        caught.exception.close()
        self.assertTrue(thread.is_alive())
        self.assertEqual(session.completed, {})
        (self.root / "continue").touch()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertIn(work.token, session.completed)

    def test_conflicting_old_submission_does_not_complete_next_job(self):
        session = self.session()
        first = self.work()
        session.run(first, release("FRI"), self.root, 5)
        proof = {**job.decode(first.result), "lease_token": first.token, "batch_number": 99}
        request = urllib.request.Request(session.endpoint + "/prover-jobs/v1/FRI/submit", data=job.encode(proof),
                                         headers={"Authorization": session.authorization})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 422)
        caught.exception.close()
        self.assertIsNone(session.current)
        second = self.work(13)
        session.run(second, release("FRI"), self.root, 5)
        self.assertEqual(job.decode(second.result)["batch_number"], 13)

    def test_deadline_and_native_crash_close_session_without_replaying(self):
        for index, mode in enumerate(("hold_before", "crash")):
            with self.subTest(mode=mode):
                session = self.session(mode)
                work = self.work(20 + index)
                with self.assertRaisesRegex(runpod.Error, "fri_session_deadline|fri_native_exited"):
                    session.run(work, release("FRI"), self.root, .4)
                self.assertTrue(session.closed)
                self.assertIsNone(work.result)
                self.assertIsNotNone(session.process.returncode)
                with self.assertRaisesRegex(runpod.Error, "fri_session_unavailable"):
                    session.run(work, release("FRI"), self.root, 1)

    def test_prewarm_waits_for_authenticated_matching_vk_pick_without_leasing_work(self):
        session = self.session("hold_setup")
        errors = []
        def prewarm():
            try:
                session.prewarm(release("FRI"), 5)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=prewarm)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.until(lambda: session.native_pid is not None and self.events())
        self.assertFalse(session.ready)
        self.assertTrue(thread.is_alive())
        route = "/prover-jobs/v1/FRI/pick?supported_vk_hashes=" + "0x" + "a1" * 32 + "&max_fri_pick_response_bytes=999999"
        for auth, path, status in ((None, route, 401),
                                   (session.authorization, route.replace("a1", "a2"), 422)):
            headers = {"Authorization": auth} if auth else {}
            request = urllib.request.Request(session.endpoint + path, method="POST", headers=headers)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request)
            self.assertEqual(caught.exception.code, status)
            caught.exception.close()
            self.assertFalse(session.ready)
        (self.root / "continue").touch()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(session.ready)
        self.assertTrue(session.usable())
        self.assertIsNone(session.current)
        self.assertEqual([event["kind"] for event in self.events()], ["init"])
        pid = session.native_pid
        session.run(self.work(), release("FRI"), self.root, 5)
        self.assertEqual(session.native_pid, pid)

    def test_absolute_deadline_after_restore_refuses_job_and_reaps_native(self):
        session = self.session()
        session.prewarm(release("FRI"), 5)
        self.assertTrue(session.usable())
        with self.assertRaisesRegex(runpod.Error, "fri_session_deadline"):
            session.run(self.work(), release("FRI"), self.root, 5, deadline_unix=time.time() - 1)
        self.assertTrue(session.closed)
        self.assertIsNotNone(session.process.returncode)
        self.assertEqual([event["kind"] for event in self.events()], ["init"])

    def test_full_timeout_admission_rejects_short_guardian_before_exposing_work(self):
        for field, now in (("deadline", time.monotonic), ("wall_deadline", time.time)):
            with self.subTest(clock=field):
                session = self.session()
                session.prewarm(release("FRI"), 5)
                setattr(session, field, now() + .5)
                self.assertTrue(session.usable())
                self.assertFalse(session.usable(1))
                work = self.work(12 if field == "deadline" else 13)
                with self.assertRaisesRegex(runpod.Error, "fri_session_insufficient_lifetime"):
                    session.run(work, release("FRI"), self.root, 1, require_full_timeout=True)
                self.assertFalse(work.picked)
                self.assertIsNone(work.result)
                self.assertTrue(session.closed)
                self.assertIsNone(session.current)

    def test_full_timeout_admission_proves_through_real_native_http_session(self):
        session = self.session()
        session.prewarm(release("FRI"), 5)
        work = self.work()
        session.run(work, release("FRI"), self.root, 2, deadline_unix=time.time() + 5,
                    require_full_timeout=True)
        self.assertTrue(work.picked)
        self.assertIsNotNone(work.result)
        self.assertTrue(session.usable())

    def test_guardian_enforces_absolute_lifetime_without_active_parent_handler(self):
        session = self.session(lifetime_seconds=20)
        session.wall_deadline = time.time() + .8
        session.prewarm(release("FRI"), 5)
        self.until(lambda: session.process.poll() is not None)
        self.assertFalse(session.usable())
        self.assertEqual([event["kind"] for event in self.events()], ["init"])

    def test_guardian_bounds_startup_independently_until_first_native_pick(self):
        session = self.session("hold_setup", lifetime_seconds=20)
        session._start(release("FRI"), .8)
        self.until(lambda: session.process.poll() is not None)
        self.assertFalse(session.ready)
        self.assertEqual([event["kind"] for event in self.events()], ["init"])

    def test_first_native_pick_releases_only_startup_bound(self):
        session = self.session(lifetime_seconds=20)
        session.prewarm(release("FRI"), .8)
        time.sleep(1)
        self.assertTrue(session.usable())
        self.assertIsNone(session.process.poll())

    def test_guardian_enforces_lifetime_while_parent_is_idle(self):
        session = self.session(lifetime_seconds=.8)
        session.run(self.work(), release("FRI"), self.root, 5)
        self.until(lambda: session.process.poll() is not None)
        self.assertLess(len(self.events()), 10)
        with self.assertRaisesRegex(runpod.Error, "fri_session_deadline"):
            session.run(self.work(13), release("FRI"), self.root, 5)

    def test_result_callback_failure_is_never_acknowledged_as_success(self):
        session = self.session()
        work = self.work()
        def fail(_):
            raise runpod.Error("persistence_failed")
        work.on_result = fail
        with self.assertRaisesRegex(runpod.Error, "fri_native_exited"):
            session.run(work, release("FRI"), self.root, 5)
        self.assertIsNone(work.result)
        self.assertTrue(work.output.exists())
        self.assertEqual(session.completed, {})

    def test_commands_keep_one_shot_default_and_warm_credentials_out_of_argv(self):
        args = fri_session.persistent_command(release("FRI"), "http://127.0.0.1:1", self.root)
        self.assertNotIn("--iterations", args)
        self.assertNotIn("--sequencer-urls", args)
        for stage in ("FRI", "SNARK"):
            once = worker.command(release(stage), "http://127.0.0.1:1", self.root)
            self.assertEqual(once[once.index("--iterations") + 1], "1")
        with patch.dict(os.environ, {"RUNPOD_API_KEY": "forbidden", "WALLET_SECRET": "forbidden"}):
            session = self.session()
            session.run(self.work(), release("FRI"), self.root, 5)
        environment = next(event["environment"] for event in self.events() if event["kind"] == "init")
        self.assertNotIn("RUNPOD_API_KEY", environment)
        self.assertNotIn("WALLET_SECRET", environment)
        self.assertIn("ZKSYNC_SEQUENCER_URLS", environment)

    def test_parent_death_kills_descendants_before_runtime_lock_is_released(self):
        parent_script = self.root / "parent.py"
        module_dir = str(Path(fri_session.__file__).parent)
        mode = "detached" if sys.platform.startswith("linux") else "descendant"
        guardian = self.guardian_script()
        parent_script.write_text(f'''import fcntl, json, os, pathlib, sys, time
sys.path.insert(0, {module_dir!r})
import fri_session, worker
from test_adapter import payload, release
fri_session.__file__ = {str(guardian)!r}
root = pathlib.Path({str(self.root)!r})
lock = (root / 'runtime.lock').open('a+')
fcntl.flock(lock, fcntl.LOCK_EX)
session = fri_session.FriSession(lock_fd=lock.fileno(), lifetime_seconds=20,
    command_factory=lambda *_: [sys.executable, {str(self.fake)!r}, str(root), {mode!r}])
session.run(worker.OneJob(payload('FRI'), release('FRI'), root / 'proof.json'), release('FRI'), root, 5)
(root / 'parent-ready').write_text(json.dumps(dict(native=session.native_pid, guardian=session.process.pid)))
time.sleep(300)
''')
        parent = subprocess.Popen([sys.executable, str(parent_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def cleanup():
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
        self.addCleanup(cleanup)
        self.until(lambda: (self.root / "parent-ready").exists())
        identities = json.loads((self.root / "parent-ready").read_text())
        with (self.root / "runtime.lock").open("a+") as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.kill(identities["guardian"], signal.SIGSTOP)
            try:
                parent.kill()
                parent.wait(timeout=5)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.kill(identities["guardian"], signal.SIGCONT)
            def acquired():
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except BlockingIOError:
                    return False
            self.until(acquired)
            descendant = next(event["child"] for event in self.events() if event["kind"] == "descendant")
            for pid in (identities["native"], descendant):
                self.until(lambda: not self.alive(pid))

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_native_exit_reaps_remaining_descendant(self):
        session = self.session("descendant_exit")
        with self.assertRaisesRegex(runpod.Error, "fri_native_exited"):
            session.run(self.work(), release("FRI"), self.root, 5)
        child = next(event["child"] for event in self.events() if event["kind"] == "descendant")
        self.until(lambda: not self.alive(child))

    def test_proc_discovery_skips_unreadable_foreign_entries_and_unusual_comm(self):
        proc = self.root / "proc"
        proc.mkdir()
        for name in ("100", "101", "102", "103"):
            (proc / name).mkdir()
        (proc / "100" / "stat").write_bytes(b"100 (foreign) S 1 0 0")
        (proc / "101" / "stat").write_bytes(b"101 (foreign) S invalid 0 0")
        (proc / "102" / "stat").write_bytes(b"102 (malformed)")
        (proc / "103" / "stat").write_bytes(b"103 (child ) with\n(parentheses)) S 42 0 0")
        read_bytes = Path.read_bytes
        def read(path):
            if path.parent.name == "100":
                raise PermissionError("unreadable_foreign_process")
            return read_bytes(path)
        paths = sorted(proc.iterdir())
        with patch.object(Path, "iterdir", return_value=iter(paths)), patch.object(Path, "read_bytes", read), \
                patch.object(os, "getpid", return_value=42):
            self.assertEqual(list(fri_session._adopted_children()), [103])

    def test_failed_child_kill_does_not_skip_other_children_or_release_ownership(self):
        with patch.object(os, "waitpid", side_effect=[(0, 0), (21, 0), (0, 0), (20, 0), ChildProcessError()]) as wait, \
                patch.object(fri_session, "_adopted_children", side_effect=[iter((20, 21)), iter((20,))]), \
                patch.object(os, "kill", side_effect=[PermissionError(), None, None]) as kill, \
                patch.object(time, "sleep"):
            fri_session._reap_adopted_children()
        self.assertEqual([call.args[0] for call in kill.call_args_list], [20, 21, 20])
        self.assertEqual(wait.call_count, 5)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper lifecycle")
    def test_missing_optional_proc_entry_reaps_detached_child_after_native_exit(self):
        guardian = self.guardian_script()
        session = self.session("detached_exit")
        with patch.object(fri_session, "__file__", str(guardian)):
            with self.assertRaisesRegex(runpod.Error, "fri_native_exited"):
                session.run(self.work(), release("FRI"), self.root, 5)
        child = next(event["child"] for event in self.events() if event["kind"] == "descendant")
        self.assertFalse(self.alive(child))
        self.assertIsNotNone(session.process.returncode)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper lifecycle")
    def test_failed_proc_enumeration_retains_lock_until_detached_child_is_reaped(self):
        guardian = self.guardian_script(block_proc=True)
        lock_path = self.root / "runtime.lock"
        lock = lock_path.open("a+")
        self.addCleanup(lock.close)
        fcntl.flock(lock, fcntl.LOCK_EX)
        session = self.session("detached_exit", lock_fd=lock.fileno())
        with patch.object(fri_session, "__file__", str(guardian)):
            thread, errors = self.run_async(session, self.work(), timeout=10)
            self.addCleanup((self.root / "allow-proc").touch)
            self.until(lambda: (self.root / "enumeration-blocked").exists())
        child = next(event["child"] for event in self.events() if event["kind"] == "descendant")
        lock.close()
        with lock_path.open("a+") as probe:
            self.assertTrue(self.alive(child))
            self.assertIsNone(session.process.poll())
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            (self.root / "allow-proc").touch()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual([str(error) for error in errors], ["fri_native_exited"])
            self.assertFalse(self.alive(child))
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)


if __name__ == "__main__":
    unittest.main()
