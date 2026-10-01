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
if mode in ('descendant', 'descendant_exit', 'detached'):
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'], start_new_session=mode == 'detached')
    event('descendant', child=child.pid)
    if mode == 'descendant_exit': os._exit(73)
last = None
count = 0
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
        parent_script.write_text(f'''import fcntl, json, os, pathlib, sys, time
sys.path.insert(0, {module_dir!r})
import fri_session, worker
from test_adapter import payload, release
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


if __name__ == "__main__":
    unittest.main()
