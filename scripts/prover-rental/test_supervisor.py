import argparse
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

import job
import pool
import runpod
import sentry
import supervisor
import warm_worker
from test_adapter import payload, release, storage_plan, successful_native
from test_pool import IDENTITIES, evidence
from test_runpod import FakeApi, policy
from test_storage import config as storage_config
from test_warm import MailboxStorage


class Objects(MailboxStorage):
    def __init__(self, clock):
        super().__init__()
        self.clock, self.plans = clock, []
        self.fail_command_once = False

    def session_plan(self, identifier):
        prefix = "https://storage.example/sessions/" + identifier
        return {"mailbox_key": prefix + "/command", "mailbox_url": prefix + "/command?get=SCOPED",
                "finished_manifest_url": prefix + "/finished?get=SCOPED",
                "finished_manifest_put_url": prefix + "/finished?put=SCOPED",
                "expires_at": int(self.clock()) + 7200}

    def job_plan(self, identifier):
        plan = {key: url.replace("storage.example/", "storage.example/jobs/" + identifier + "/")
                for key, url in storage_plan().items()}
        self.plans.append((identifier, plan))
        return plan

    def job_transport(self, identifier, plan):
        return self

    def publish_command(self, identifier, raw):
        self.put("https://storage.example/sessions/" + identifier + "/command", raw)
        if self.fail_command_once:
            self.fail_command_once = False
            raise runpod.Error("ambiguous_mailbox_put")


class Native:
    def __init__(self):
        self.calls, self.ready = [], set()
        self.pick_failure, self.evidence_wrong = None, False
        self.submit_response = (204, {"x-syscoin-prover-disposition": "accepted"}, b"")

    def request(self, url, method="GET", data=None, authorization=None, maximum=None):
        self.calls.append((url, method, data, authorization))
        name = "child" if urllib.parse.urlsplit(url).port == 3125 else "gateway"
        stage = "FRI" if "/FRI/" in url else "SNARK"
        if "/pick?" in url:
            if self.pick_failure == "transport":
                raise runpod.Error("transport_failure")
            if self.pick_failure == "unmarked":
                return 204, {}, b""
            if (name, stage) not in self.ready:
                return 204, {"x-syscoin-prover-pick-outcome": "unleased"}, b""
            self.ready.remove((name, stage))
            return 200, {}, job.encode({**payload(stage), "lease_token": "0x" + "f1" * 32})
        if url.endswith("/evidence"):
            return 200, {}, job.encode(evidence("gateway" if self.evidence_wrong else name, stage))
        if "/submit?" in url:
            assert job.decode(data)["lease_token"] == "0x" + "f1" * 32
            assert authorization.endswith("Y2hpbGQ6c2VjcmV0" if name == "child" else "Z2F0ZXdheTpzZWNyZXQ=")
            return self.submit_response
        raise AssertionError("unexpected native endpoint")


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root, self.now = Path(self.temporary.name), 1000
        self.provider = runpod.Store.initialize(self.root / "provider", policy())
        self.lock = self.provider.lock("watchdog.lock")
        self.lock.__enter__()
        self.addCleanup(self.lock.__exit__, None, None, None)
        self.provider.heartbeat(self.now)
        self.native, self.api = Native(), FakeApi()
        self.objects = Objects(lambda: self.now)
        self.config = {"schema_version": 1, "mode": "native-compute", "provider_state_dir": str(self.provider.root),
            "releases": {}, "storage": storage_config(), "poll_interval_seconds": 1,
            "idle_grace_seconds": 30, "startup_reserve_seconds": 15,
            "runtime_seconds": {"FRI": 60, "SNARK": 120}, "sequencers": [], "external_pool_dirs": []}
        for stage in ("FRI", "SNARK"):
            path = self.root / (stage + "-release.json")
            job.write_new(path, job.encode(release(stage)))
            self.config["releases"][stage] = str(path)
        for index, name in enumerate(("child", "gateway")):
            auth = self.root / (name + "-auth.txt")
            job.write_new(auth, (name + ":secret").encode())
            self.config["sequencers"].append({"name": name, "lane": name,
                "endpoint": f"http://127.0.0.1:{3125-index}/", "auth_file": str(auth),
                "identity": IDENTITIES[name], "native_lease_seconds": 7200, "stages": ["FRI", "SNARK"]})
        self.store = supervisor.initialize(self.root / "supervisor", self.config)
        self.reload()
        self.seen = []

    def reload(self):
        self.instance = supervisor.Supervisor(self.store, self.api, self.objects, self.native,
            clock=lambda: self.now, controller_http=self.objects, service_rpc=getattr(self, "service_rpc", None))
        return self.instance

    def count(self, kind):
        return len([call for call in self.api.calls if call[0] == kind])

    def picks(self):
        return [call for call in self.native.calls if "/pick?" in call[0]]

    def advance(self, seconds):
        self.now += seconds
        self.provider.heartbeat(self.now)

    def pod(self):
        session = self.instance.state["session"]
        descriptor = session["descriptor"]
        args = argparse.Namespace(operation_id=session["operation"], session_id=descriptor["session_id"],
            session_key=descriptor["session_key"], mailbox_url=descriptor["mailbox_url"],
            finished_manifest_put_url=descriptor["finished_manifest_put_url"], deadline_unix=session["deadline"],
            runtime_limit_seconds=3600, poll_interval_seconds=1, state_dir=str(self.root / "pod"))
        def native(args, directory, timeout):
            stage = next(stage for stage, binary in job.BINARIES.items() if args[0] == binary)
            return successful_native(stage, self.seen)(args, directory, timeout)
        return warm_worker.WarmWorker(args, self.objects, clock=lambda: self.now,
            release_dir=self.store.root / "releases", verify=lambda _: None, native=native)

    def complete(self):
        self.assertEqual(self.pod().tick(), "completed")
        self.instance.tick()
        self.assertIsNone(self.instance.state["active"])

    def test_actual_snark_pick_precedes_fri_and_same_gpu_reuses_both_stages(self):
        self.native.ready.update({("child", "FRI"), ("gateway", "SNARK")})
        self.instance.tick()
        self.assertEqual(self.instance.state["active"]["stage"], "SNARK")
        self.assertEqual(len(self.picks()), 2)
        self.assertTrue(all("/SNARK/" in call[0] for call in self.picks()))
        self.complete()
        self.reload().tick()
        self.assertEqual(self.instance.state["active"]["stage"], "FRI")
        self.complete()
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.count("delete"), 0)
        self.assertEqual(len(self.seen), 2)
        self.assertEqual(self.instance.state["completed_jobs"], 2)
        for raw in self.objects.objects.values():
            self.assertNotIn(b"f1" * 32, raw)
            self.assertNotIn(b"secret", raw)
            self.assertNotIn(b"127.0.0.1", raw)
        request = next(call[1] for call in self.api.calls if call[0] == "create")
        self.assertNotIn("secret", json.dumps(request))
        self.assertNotIn("lease_token", json.dumps(request))

    def test_unknown_or_unmarked_pick_survives_restart_and_blocks_all_other_work(self):
        for failure in ("transport", "unmarked"):
            with self.subTest(failure=failure):
                self.store = supervisor.initialize(self.root / failure, self.config)
                self.native = Native()
                self.reload()
                self.native.pick_failure = failure
                with self.assertRaises(runpod.Error):
                    self.instance.tick()
                active = copy.deepcopy(self.instance.state["active"])
                count = len(self.picks())
                self.native.pick_failure = None
                with self.assertRaises(runpod.Error):
                    self.reload().tick()
                self.assertEqual(self.instance.state["active"], active)
                self.assertEqual(len(self.picks()), count)
                self.assertEqual(self.count("create"), 0)

    def test_pre_authority_crashes_resume_once_with_same_identity_and_refreshed_deadline(self):
        for window in ("before_directory", "empty_directory", "partial_temporary", "complete_temporary"):
            with self.subTest(window=window):
                self.store = supervisor.initialize(self.root / window, self.config)
                self.native = Native()
                self.native.ready.add(("child", "SNARK"))
                self.reload()
                source = self.instance.source("child")
                def interrupted_authority(path, value):
                    self.assertEqual(path.name, "authority.json")
                    if window.endswith("temporary"):
                        raw = job.encode(value)
                        if window == "partial_temporary":
                            raw = raw[:len(raw) // 2]
                        job.write_new(path.with_name(".authority.json." + "a" * 32 + ".tmp"), raw)
                    raise KeyboardInterrupt()
                interrupted = patch.object(sentry, "pick", side_effect=KeyboardInterrupt()) if window == "before_directory" \
                    else patch.object(sentry, "atomic_json", side_effect=interrupted_authority)
                with interrupted, self.assertRaises(KeyboardInterrupt):
                    self.instance.pick_native(source, "SNARK")
                original = copy.deepcopy(self.instance.state["active"])
                self.assertEqual(self.picks(), [])
                self.advance(source["native_lease_seconds"] + 1)
                self.reload()
                request = self.native.request
                def checked_request(url, *args, **kwargs):
                    if "/pick?" in url:
                        retained = runpod.read_private_json(self.store.root / "supervisor.json")["active"]
                        self.assertEqual(retained["id"], original["id"])
                        self.assertEqual(retained["job_id"], original["job_id"])
                        self.assertEqual(retained["picked_at"], self.now)
                        self.assertEqual(retained["deadline"], self.now + source["native_lease_seconds"])
                        self.assertEqual(runpod.read_private_json(self.instance.directory() / "authority.json")["status"],
                                         "pick_uncertain")
                    return request(url, *args, **kwargs)
                with patch.object(self.native, "request", side_effect=checked_request):
                    self.assertTrue(self.instance.recover_native_pick(self.instance.state["active"]))
                self.assertEqual(len(self.picks()), 1)
                self.assertEqual(self.instance.state["active"]["phase"], "ready")
                self.instance.compute_window(self.instance.state["active"])
                self.assertFalse(any(self.instance.directory().glob("*.tmp")))
                self.assertEqual(self.count("create"), 0)

    def test_uncertain_authority_before_release_never_restarts_or_refreshes_deadline(self):
        source = self.instance.source("child")
        with patch.object(sentry.job, "write_new", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.instance.pick_native(source, "SNARK")
        original = copy.deepcopy(self.instance.state["active"])
        authority = (self.instance.directory() / "authority.json").read_bytes()
        self.assertEqual(self.picks(), [])
        self.advance(source["native_lease_seconds"] + 1)
        with self.assertRaises(FileNotFoundError):
            self.reload().recover_native_pick(self.instance.state["active"])
        self.assertEqual(self.instance.state["active"], original)
        self.assertEqual((self.instance.directory() / "authority.json").read_bytes(), authority)
        self.assertEqual(self.picks(), [])

    def test_completed_wire_recovery_preserves_original_deadline_without_another_pick(self):
        source = self.instance.source("child")
        self.native.ready.add(("child", "SNARK"))
        with patch.object(sentry, "recover_pick", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.instance.pick_native(source, "SNARK")
        original = copy.deepcopy(self.instance.state["active"])
        wire = (self.instance.directory() / "picked-wire.json").read_bytes()
        self.advance(source["native_lease_seconds"] + 1)
        self.reload()
        self.assertTrue(self.instance.recover_native_pick(self.instance.state["active"]))
        self.assertEqual(len(self.picks()), 1)
        for field in ("id", "job_id", "picked_at", "deadline"):
            self.assertEqual(self.instance.state["active"][field], original[field])
        self.assertEqual((self.instance.directory() / "picked-wire.json").read_bytes(), wire)
        self.assertEqual(self.instance.state["active"]["phase"], "ready")

    def test_unknown_pre_authority_artifact_blocks_recovery_without_changes(self):
        source = self.instance.source("child")
        with patch.object(sentry, "atomic_json", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.instance.pick_native(source, "SNARK")
        original = copy.deepcopy(self.instance.state["active"])
        directory = self.instance.directory()
        job.write_new(directory / "picked-wire.json", b"retained-response")
        self.advance(source["native_lease_seconds"] + 1)
        with self.assertRaisesRegex(runpod.Error, "pick_initialization_contains_unknown_artifacts"):
            self.reload().recover_native_pick(self.instance.state["active"])
        self.assertEqual(self.instance.state["active"], original)
        self.assertEqual((directory / "picked-wire.json").read_bytes(), b"retained-response")
        self.assertEqual(self.picks(), [])

    def test_pre_authority_recovery_checks_capacity_before_request_or_deadline_refresh(self):
        source = self.instance.source("child")
        with patch.object(sentry, "atomic_json", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.instance.pick_native(source, "SNARK")
        original = copy.deepcopy(self.instance.state["active"])
        self.advance(source["native_lease_seconds"] + 1)
        with patch.object(runpod.Controller, "check_session_capacity", side_effect=runpod.Error("state_admission_capacity")), \
                self.assertRaisesRegex(runpod.Error, "state_admission_capacity"):
            self.reload().recover_native_pick(self.instance.state["active"])
        self.assertEqual(self.instance.state["active"], original)
        self.assertEqual(self.picks(), [])

    def test_warm_capacity_is_checked_before_next_native_pick(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.complete()
        calls = len(self.picks())
        self.native.ready.add(("child", "FRI"))
        with patch.object(runpod.Controller, "check_warm_job_capacity", side_effect=runpod.Error("state_admission_capacity")), \
                self.assertRaisesRegex(runpod.Error, "state_admission_capacity"):
            self.instance.tick()
        self.assertEqual(len(self.picks()), calls)
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.count("create"), 1)

    def test_warm_capacity_is_checked_before_next_external_claim(self):
        external = self.external_pool()
        self.enqueue_external_fri(external, "dispatcher:first", 1300)
        self.instance.tick()
        self.complete()
        pending = self.enqueue_external_fri(external, "dispatcher:next", 1300)
        with patch.object(runpod.Controller, "check_warm_job_capacity", side_effect=runpod.Error("state_admission_capacity")), \
                self.assertRaisesRegex(runpod.Error, "state_admission_capacity"):
            self.instance.tick()
        op = pool.Pool(external.store, clock=lambda: self.now).operation(pending)
        self.assertEqual(op["status"], "ready")
        self.assertNotIn("warm_owner", op)
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.picks(), [])

    def external_pool(self, service=None):
        config = {"schema_version": 1, "limits": {"max_inflight_jobs": 4, "lifetime_budget_usd": "20"}, "lanes": {}}
        rental_policy = policy()
        rental_policy["limits"]["max_runtime_seconds"] = 50
        policy_path = self.root / "external-policy.json"
        job.write_new(policy_path, job.encode(rental_policy))
        for source in self.config["sequencers"]:
            config["lanes"][source["name"]] = {key: copy.deepcopy(source[key]) for key in
                ("endpoint", "auth_file", "identity", "native_lease_seconds")}
            config["lanes"][source["name"]].update(limits={"max_inflight_jobs": 2, "lifetime_budget_usd": "10"},
                stages={stage: {"acquisition": "external" if stage == "FRI" else "native",
                    "release_file": self.config["releases"][stage], "rental_policy_file": str(policy_path)}
                    for stage in ("FRI", "SNARK")})
        if service is not None:
            service_path = self.root / "keeper-config.json"
            job.write_new(service_path, job.encode(service))
            config["lanes"]["child"]["stages"]["SNARK"].update(acquisition="external",
                service={"keeper_config_file": str(service_path)})
            config["lanes"]["child"]["auth_file"] = None
        external_store = pool.initialize(self.root / "external-pool", config)
        config = {**self.config, "mode": "decentralized-service", "sequencers": [],
                  "external_pool_dirs": [str(external_store.root)]}
        self.store = supervisor.initialize(self.root / "external-supervisor", config)
        self.reload()
        return pool.Pool(external_store, clock=lambda: self.now)

    def service_pool(self):
        if "ZKSYNC_OS_SERVER_DIR" not in os.environ:
            self.skipTest("cross-repository service tests require ZKSYNC_OS_SERVER_DIR")
        keeper = pool.service_keeper()
        from test_keeper import NativeRpc, setup
        from test_service import fixture
        f = fixture()
        service, request, item = setup(f)
        rpc = NativeRpc(f, service, item)
        permit = keeper.permit(service, rpc, request, f["evidence"], f["fri_payload"], self.now, 50)
        for stage, path in self.config["releases"].items():
            runpod.atomic_json(Path(path), {**release(stage), "vk_hash": service["settings"]["vk_hash"]})
        for entry in self.config["sequencers"]:
            entry["identity"] = {**entry["identity"], "vk_hash": service["settings"]["vk_hash"]}
        self.config["sequencers"][0]["identity"] = {key: f["evidence"][key] for key in IDENTITIES["child"]}
        external = self.external_pool(service)
        self.service_rpc = self.instance.service_rpc = rpc
        operation = external.enqueue("child", "SNARK", "selected-wrapper:1", job.encode(f["fri_payload"]),
                                     f["evidence"], 1200, permit)
        return external, operation, rpc

    def test_service_stale_selected_turn_retires_unstarted_work_without_losing_payload(self):
        external, operation, rpc = self.service_pool()
        rpc.turn += 1
        self.instance.tick()
        self.assertEqual(self.count("create"), 0)
        self.assertEqual(self.objects.objects, {})
        retained = pool.Pool(external.store, clock=lambda: self.now).operation(operation)
        self.assertEqual(retained["status"], "authorization_expired")
        self.assertEqual(retained["authorization_expired_reason"], "stale_wrapper_turn")
        self.assertEqual(retained["job_id"], "selected-wrapper:1")
        self.assertTrue((external.directory(operation) / "payload.json").exists())
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.native.calls, [])

    def test_service_turn_changes_during_provider_creation_block_job_publication(self):
        external, operation, rpc = self.service_pool()
        create = self.api.create
        def changed(request):
            result = create(request)
            rpc.turn += 1
            return result
        with patch.object(self.api, "create", changed):
            self.instance.tick()
        self.assertEqual(self.count("create"), 1)
        session = self.instance.state["session"]
        op = self.provider.load()["operations"][session["operation"]]
        self.assertIsNone(op["command"])
        self.assertEqual(op["jobs"], [])
        self.assertIsNone(self.instance.state["active"])
        retired = pool.Pool(external.store, clock=lambda: self.now).operation(operation)
        self.assertEqual(retired["status"], "authorization_expired")
        self.assertNotEqual(retired["reserved_usd"], "0")
        self.enqueue_external_fri(external, "dispatcher:after-stale-turn", 1300)
        self.instance.tick()
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.instance.state["active"]["stage"], "FRI")
        self.assertEqual(self.instance.state["session"]["operation"], session["operation"])

    def enqueue_external_fri(self, external, job_id, deadline):
        refreshed = pool.Pool(external.store, clock=lambda: self.now)
        identity = refreshed.settings["lanes"]["child"]["identity"]
        operation = refreshed.enqueue("child", "FRI", job_id,
                                job.encode({**payload("FRI"), "vk_hash": identity["vk_hash"]}),
                                {**evidence("child", "FRI"), **identity}, deadline)
        external.state = refreshed.state
        return operation

    def test_elapsed_queued_snark_window_does_not_starve_fri_or_spend_budget(self):
        external, operation, _ = self.service_pool()
        self.advance(140)
        fri = self.enqueue_external_fri(external, "dispatcher:available-fri", 1400)
        self.instance.tick()
        state = pool.Pool(external.store, clock=lambda: self.now)
        retired = state.operation(operation)
        self.assertEqual(retired["status"], "authorization_expired")
        self.assertEqual(retired["reserved_usd"], "0")
        self.assertNotEqual(retired["released_reserved_usd"], "0")
        self.assertNotIn("warm_owner", retired)
        self.assertEqual(self.instance.state["active"]["pool_operation"], fri)
        self.assertEqual(self.instance.state["active"]["stage"], "FRI")
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.native.calls, [])

    def test_crash_before_queued_retirement_retries_without_claiming_stale_job(self):
        external, operation, _ = self.service_pool()
        self.advance(140)
        fri = self.enqueue_external_fri(external, "dispatcher:after-retirement-crash", 1400)
        original = pool.Pool.save
        def crash(candidate):
            if candidate.state["operations"][operation]["status"] == "authorization_expired":
                raise KeyboardInterrupt
            original(candidate)
        with patch.object(pool.Pool, "save", crash), self.assertRaises(KeyboardInterrupt):
            self.instance.tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "ready")
        self.reload().tick()
        self.assertEqual(self.instance.state["active"]["pool_operation"], fri)
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "authorization_expired")
        self.assertEqual(self.count("create"), 1)

    def test_unstarted_active_retirement_recovers_from_durable_intent_crash(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:retirement-intent", 1100)
        self.assertTrue(self.instance.claim_external("FRI"))
        identifier = self.instance.state["active"]["id"]
        self.advance(36)
        original = supervisor.atomic_json
        def crash(path, value):
            original(path, value)
            if path.parent.name == "retired":
                raise KeyboardInterrupt
        with patch.object(supervisor, "atomic_json", crash), self.assertRaises(KeyboardInterrupt):
            self.instance.tick()
        retained = runpod.read_private_json(self.store.root / "retired" / (identifier + ".json"))
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "warm_claimed")
        self.reload().tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "authorization_expired")
        self.assertEqual(runpod.read_private_json(self.store.root / "retired" / (identifier + ".json")), retained)
        self.assertEqual(self.count("create"), 0)
        self.assertTrue((external.directory(operation) / "payload.json").exists())

    def test_claim_intent_crash_can_retire_without_provider_execution(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:claim-intent", 1100)
        with patch.object(pool.Pool, "save", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.instance.claim_external("FRI")
        self.assertEqual(self.instance.state["active"]["phase"], "claim_intent")
        self.advance(36)
        self.reload().tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "authorization_expired")
        self.assertEqual(self.count("create"), 0)

    def test_another_worker_can_retire_queue_after_claim_intent_crash(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:shared-retirement", 1100)
        with patch.object(pool.Pool, "save", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.instance.claim_external("FRI")
        self.advance(36)
        config = {**self.config, "mode": "decentralized-service", "sequencers": [],
                  "external_pool_dirs": [str(external.store.root)]}
        other_store = supervisor.initialize(self.root / "other-worker", config)
        other = supervisor.Supervisor(other_store, self.api, self.objects, self.native,
                                      clock=lambda: self.now, controller_http=self.objects)
        other.tick()
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "authorization_expired")
        self.reload().tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.count("create"), 0)

    def test_rpc_outage_does_not_retire_external_authorization(self):
        external, operation, rpc = self.service_pool()
        keeper = pool.service_keeper()
        with patch.object(rpc, "call", side_effect=keeper.s.Error("rpc_transport_failed")):
            with self.assertRaisesRegex(runpod.Error, "rpc_transport_failed"):
                self.instance.tick()
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "warm_claimed")
        self.assertEqual(self.instance.state["active"]["pool_operation"], operation)
        self.assertEqual(list((self.store.root / "retired").iterdir()), [])
        self.assertEqual(self.count("create"), 0)

    def test_ambiguous_published_job_stays_owned_after_authorization_expires(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:ambiguous-publish", 1200)
        self.objects.fail_command_once = True
        with self.assertRaisesRegex(runpod.Error, "ambiguous_mailbox_put"):
            self.instance.tick()
        identifier = self.instance.state["active"]["id"]
        # Simulate a crash before the supervisor records the provider's durable job intent.
        self.instance.state["active"].update(phase="exported", rental_operation=None)
        self.instance.save()
        self.advance(201)
        self.reload().tick()
        self.assertEqual(self.instance.state["active"]["rental_operation"], identifier)
        self.assertEqual(self.instance.state["active"]["phase"], "published")
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "warm_claimed")
        self.assertEqual(list((self.store.root / "retired").iterdir()), [])
        self.assertEqual(self.count("create"), 1)

    def test_published_external_job_auto_expires_only_after_provider_stops(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:automatic-expiry", 1200)
        self.instance.tick()
        self.advance(201)
        self.instance.tick()
        self.assertIsNotNone(self.instance.state["active"])
        self.advance(3400)
        self.reload().tick(acquire=False)
        self.assertIsNone(self.instance.state["active"])
        self.assertIsNone(self.instance.state["session"])
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "lease_expired")
        self.assertEqual(self.count("delete"), 1)

    def test_late_result_wins_over_automatic_external_expiry(self):
        external = self.external_pool()
        operation = self.enqueue_external_fri(external, "dispatcher:late-result", 1200)
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        self.advance(3601)
        original = runpod.Controller.collect
        missed = []
        def first_miss(controller, operation_id):
            if not missed:
                missed.append(operation_id)
                return False
            return original(controller, operation_id)
        with patch.object(runpod.Controller, "collect", first_miss):
            self.instance.tick(acquire=False)
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(pool.Pool(external.store).operation(operation)["status"], "returned")
        self.assertEqual(self.instance.state["completed_jobs"], 1)
        self.assertEqual(list((self.store.root / "expired").iterdir()), [])
        self.assertTrue((external.directory(operation) / "returned-proof.json").exists())

    def test_completed_job_recovers_while_mailbox_writes_are_unavailable(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        with patch.object(self.objects, "publish_command", side_effect=runpod.Error("storage_down")):
            self.reload().tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.instance.state["completed_jobs"], 1)

    def test_external_dispatch_job_returns_to_original_pool_and_cannot_expire_while_warm_owned(self):
        external = self.external_pool()
        operation = external.enqueue("child", "FRI", "dispatcher:duty:1", job.encode(payload("FRI")),
                                     evidence("child", "FRI"), 1200)
        self.instance.tick()
        external = pool.Pool(external.store, clock=lambda: self.now)
        with self.assertRaisesRegex(runpod.Error, "warm_claim_requires"):
            external.expire(operation)
        with self.assertRaisesRegex(runpod.Error, "warm_claim_requires"):
            external.complete(operation)
        self.complete()
        external = pool.Pool(external.store, clock=lambda: self.now)
        self.assertEqual(external.operation(operation)["status"], "returned")
        self.assertEqual(external.complete(operation), "returned")
        self.assertTrue((external.directory(operation) / "returned-proof.json").exists())
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.count("delete"), 0)

    def test_completion_interruption_after_provider_disposition_recovers_without_counting_twice(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        original = runpod.Controller.finish_warm_job
        def interrupted(controller, *args):
            original(controller, *args)
            raise KeyboardInterrupt
        with patch.object(runpod.Controller, "finish_warm_job", interrupted), self.assertRaises(KeyboardInterrupt):
            self.instance.tick()
        self.reload().tick()
        self.assertEqual(self.instance.state["completed_jobs"], 1)
        self.assertEqual(len([call for call in self.native.calls if "/submit?" in call[0]]), 1)
        self.assertEqual(len(self.seen), 1)

    def test_identity_mismatch_preserves_lease_before_any_rental_or_export(self):
        self.native.ready.add(("child", "SNARK"))
        self.native.evidence_wrong = True
        with self.assertRaisesRegex(runpod.Error, "identity_mismatch"):
            self.instance.tick()
        self.assertEqual(self.count("create"), 0)
        self.assertEqual(self.objects.objects, {})
        self.assertEqual(runpod.read_private_json(self.instance.directory() / "authority.json")["status"], "picked")

    def test_submit_ambiguity_retries_exact_bytes_without_recompute_or_new_pick(self):
        self.native.ready.add(("child", "SNARK"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        self.native.submit_response = (503, {}, b"")
        with self.assertRaisesRegex(runpod.Error, "submission_retained"):
            self.instance.tick()
        retained = job.read_file(self.instance.directory() / "submission.json", job.MAX_SUBMIT, private=True)
        count = len(self.picks())
        self.native.submit_response = (204, {"x-syscoin-prover-disposition": "accepted"}, b"")
        self.reload().tick()
        submissions = [call[2] for call in self.native.calls if "/submit?" in call[0]]
        self.assertEqual(submissions, [retained, retained])
        self.assertEqual(len(self.picks()), count)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(self.instance.state["completed_jobs"], 1)

    def test_mailbox_ambiguity_republishes_same_job_and_plan_after_restart(self):
        self.native.ready.add(("child", "FRI"))
        self.objects.fail_command_once = True
        with self.assertRaisesRegex(runpod.Error, "ambiguous_mailbox"):
            self.instance.tick()
        before = copy.deepcopy(self.instance.state["active"])
        command = self.objects.objects[self.objects.key(self.instance.state["session"]["descriptor"]["mailbox_url"])]
        self.reload().tick()
        self.assertEqual(self.instance.state["active"], before)
        self.assertEqual(self.objects.objects[self.objects.key(self.instance.state["session"]["descriptor"]["mailbox_url"])], command)
        self.assertEqual(len(self.objects.plans), 1)
        self.assertEqual(self.count("create"), 1)
        self.complete()

    def test_ambiguous_provider_creation_reconciles_existing_pod_without_second_post(self):
        self.native.ready.add(("child", "SNARK"))
        self.api.create_error = runpod.Error("transport_failure")
        with self.assertRaisesRegex(runpod.Error, "allocation_pending"):
            self.instance.tick()
        self.api.hide_all = True
        with self.assertRaisesRegex(runpod.Error, "allocation_pending"):
            self.reload().tick()
        self.api.hide_all = False
        self.reload().tick()
        self.assertEqual(self.instance.state["active"]["phase"], "published")
        self.assertEqual(self.count("create"), 1)

    def test_idle_grace_requires_all_marked_empty_then_finished_receipt_before_delete(self):
        self.native.ready.add(("child", "SNARK"))
        self.instance.tick()
        self.complete()
        self.instance.tick()
        self.assertEqual(self.instance.state["idle_since"], self.now)
        self.assertEqual(len(list((self.store.root / "jobs").iterdir())), 1)
        self.advance(29)
        self.instance.tick()
        self.assertFalse(self.instance.state["session"]["stopping"])
        self.advance(1)
        self.instance.tick()
        self.assertTrue(self.instance.state["session"]["stopping"])
        self.assertEqual(self.count("delete"), 0)
        self.assertEqual(self.pod().tick(), "finished")
        self.instance.tick(acquire=False)
        self.assertEqual(self.count("delete"), 1)
        self.assertIsNone(self.instance.state["session"])

    def test_outage_resets_idle_without_treating_it_as_empty_or_stopping_pending_job(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.complete()
        self.instance.tick()
        self.advance(31)
        self.native.pick_failure = "transport"
        with self.assertRaises(runpod.Error):
            self.instance.tick()
        self.assertIsNone(self.instance.state["idle_since"])
        self.assertFalse(self.instance.state["session"]["stopping"])
        self.assertEqual(self.count("delete"), 0)

    def test_hard_deadline_cleans_provider_but_preserves_active_job_for_recovery(self):
        self.native.ready.add(("child", "SNARK"))
        self.instance.tick()
        identifier = self.instance.state["active"]["id"]
        self.advance(3600)
        self.instance.tick(acquire=False)
        self.assertEqual(self.count("delete"), 1)
        self.assertEqual(self.instance.state["active"]["id"], identifier)
        self.assertEqual(self.count("create"), 1)

    def test_session_without_room_rotates_before_acquiring_another_lease(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.complete()
        count = len(self.picks())
        self.advance(3600 - 130)
        self.instance.tick()
        self.assertEqual(len(self.picks()), count)
        self.assertTrue(self.instance.state["session"]["stopping"])

    def test_expiration_uses_completed_response_time_and_preserves_all_authority_files(self):
        self.native.ready.add(("child", "FRI"))
        request = self.native.request
        def slow(url, *args, **kwargs):
            result = request(url, *args, **kwargs)
            if "/FRI/pick?" in url:
                self.advance(20)
            return result
        with patch.object(self.native, "request", slow):
            self.instance.tick()
        active = copy.deepcopy(self.instance.state["active"])
        directory = self.instance.directory()
        self.assertEqual(active["deadline"], 8200)
        self.assertEqual(active["expiry_not_before"], 8220)
        count = len(self.picks())
        self.advance(7181)
        with self.assertRaisesRegex(runpod.Error, "native_lease_not_expired"):
            self.instance.expire_active()
        self.advance(19)
        self.assertEqual(self.instance.expire_active(), "expired")
        self.assertIsNone(self.instance.state["active"])
        self.assertIsNone(self.instance.state["session"])
        self.assertEqual(len(self.picks()), count)
        self.assertTrue((directory / "authority.json").exists())
        self.assertTrue((directory / "payload.json").exists())
        self.assertEqual(runpod.read_private_json(self.store.root / "expired" / (active["id"] + ".json"))["active"], active)
        self.assertEqual(self.count("delete"), 1)

    def test_unknown_pick_and_unresolved_native_submission_never_expire(self):
        self.native.pick_failure = "transport"
        with self.assertRaises(runpod.Error):
            self.instance.tick()
        self.advance(9000)
        with self.assertRaisesRegex(runpod.Error, "origin_reconciliation"):
            self.instance.expire_active()
        self.assertIsNotNone(self.instance.state["active"])
        self.store = supervisor.initialize(self.root / "submission-supervisor", self.config)
        self.native = Native()
        self.reload()
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        self.native.submit_response = (503, {}, b"")
        with self.assertRaisesRegex(runpod.Error, "submission_retained"):
            self.instance.tick()
        self.advance(7201)
        with self.assertRaisesRegex(runpod.Error, "submission_retained"):
            self.instance.expire_active()
        self.native.submit_response = (204, {"x-syscoin-prover-disposition": "accepted"}, b"")
        self.assertEqual(self.instance.expire_active(), "completed")
        self.assertEqual(list((self.store.root / "expired").iterdir()), [])

    def test_expired_external_offer_cannot_release_claim_while_provider_is_running(self):
        external = self.external_pool()
        operation = external.enqueue("child", "FRI", "dispatcher:expiry:1", job.encode(payload("FRI")),
                                     evidence("child", "FRI"), 1200)
        self.instance.tick()
        self.advance(201)
        with self.assertRaisesRegex(runpod.Error, "provider_must_be_reconciled_and_stopped"):
            self.instance.expire_active()
        self.advance(3400)
        self.assertEqual(self.instance.expire_active(), "expired")
        external = pool.Pool(external.store, clock=lambda: self.now)
        self.assertEqual(external.operation(operation)["status"], "lease_expired")
        self.assertTrue((external.directory(operation) / "payload.json").exists())

    def test_expiration_archive_crash_is_idempotent_and_does_not_issue_another_pick(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        identifier = self.instance.state["active"]["id"]
        count = len(self.picks())
        self.advance(7201)
        original = supervisor.atomic_json
        def interrupt(path, value):
            original(path, value)
            if path.parent.name == "expired":
                raise KeyboardInterrupt
        with patch.object(supervisor, "atomic_json", interrupt), self.assertRaises(KeyboardInterrupt):
            self.instance.expire_active()
        archived = runpod.read_private_json(self.store.root / "expired" / (identifier + ".json"))
        self.advance(1)
        self.assertEqual(self.reload().expire_active(), "expired")
        self.assertEqual(runpod.read_private_json(self.store.root / "expired" / (identifier + ".json")), archived)
        self.assertEqual(len(self.picks()), count)
        self.assertEqual(self.count("delete"), 1)

    def test_late_result_after_durable_retirement_never_changes_disposition_or_submits(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        identifier = self.instance.state["active"]["id"]
        self.assertEqual(self.pod().tick(), "completed")
        selected = runpod.read_private_json(self.instance.directory() / "controller-job.json")
        result_key = self.objects.key(selected["result_manifest_url"])
        delayed = self.objects.objects.pop(result_key)
        self.advance(7201)
        original = runpod.Controller.finish_warm_job
        def interrupt(controller, *args):
            original(controller, *args)
            raise KeyboardInterrupt
        with patch.object(runpod.Controller, "finish_warm_job", interrupt), self.assertRaises(KeyboardInterrupt):
            self.instance.expire_active()
        self.objects.objects[result_key] = delayed
        count = len(self.picks())
        self.reload().tick(acquire=False)
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.provider.load()["operations"][identifier]["disposition"], "failed")
        self.assertEqual(len([call for call in self.native.calls if "/submit?" in call[0]]), 0)
        self.assertEqual(len(self.picks()), count)
        self.assertEqual(self.objects.objects[result_key], delayed)
        self.assertEqual(len(self.seen), 1)

    def test_crash_between_provider_and_supervisor_journals_recovers_after_compute_window(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        self.instance.state["active"].update(phase="exported", rental_operation=None)
        self.instance.state["session"]["operation"] = None
        self.instance.save()
        self.advance(7201)
        self.reload().tick(acquire=False)
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.instance.state["completed_jobs"], 1)
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(len(self.seen), 1)

    def test_archived_finished_job_recovers_before_supervisor_completion_save(self):
        self.native.ready.add(("child", "FRI"))
        self.instance.tick()
        self.assertEqual(self.pod().tick(), "completed")
        active = copy.deepcopy(self.instance.state["active"])
        finish = runpod.Controller.finish_warm_job
        def crash_after_archive(controller, *args):
            finish(controller, *args)
            raise KeyboardInterrupt()
        with patch.object(runpod.Controller, "finish_warm_job", crash_after_archive), self.assertRaises(KeyboardInterrupt):
            self.instance.tick()
        self.assertEqual(self.instance.state["active"], active)
        self.assertEqual(self.instance.state["completed_jobs"], 0)
        self.assertNotIn(active["id"], self.provider.load()["operations"])
        archived = runpod.Controller(self.provider, self.api, clock=lambda: self.now).find_operation(active["id"])
        self.assertEqual(archived["disposition"], "accepted")
        proof = (self.provider.root / (active["id"] + ".proof")).read_bytes()
        submission = (self.instance.directory() / "submission.json").read_bytes()
        picks = len(self.picks())
        self.reload().tick()
        self.assertIsNone(self.instance.state["active"])
        self.assertEqual(self.instance.state["completed_jobs"], 1)
        self.assertEqual(self.instance.state["session"]["jobs"], 1)
        self.assertEqual(len(self.picks()), picks)
        self.assertEqual(len([call for call in self.native.calls if "/submit?" in call[0]]), 1)
        self.assertEqual(self.count("create"), 1)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual((self.provider.root / (active["id"] + ".proof")).read_bytes(), proof)
        self.assertEqual((self.instance.directory(active) / "submission.json").read_bytes(), submission)

    def test_ten_busy_workers_share_real_queue_without_prefetch_or_extra_provider_capacity(self):
        state = self.provider.load()
        state["policy"]["limits"].update(max_concurrent_pods=10, lifetime_budget_usd="20")
        self.provider.save(state)
        selected = copy.deepcopy(self.config)
        selected["sequencers"] = [selected["sequencers"][0]]
        selected["sequencers"][0]["stages"] = ["FRI"]
        queue, issued = list(range(12, 112)), []
        request = self.native.request
        def shared_queue(url, method="GET", data=None, authorization=None, maximum=None):
            if "/pick?" in url:
                self.native.calls.append((url, method, data, authorization))
                if not queue:
                    return 204, {"x-syscoin-prover-pick-outcome": "unleased"}, b""
                number = queue.pop(0)
                issued.append(number)
                return 200, {}, job.encode({**payload("FRI"), "batch_number": number,
                    "lease_token": "0x" + "f1" * 32})
            if url.endswith("/evidence"):
                self.native.calls.append((url, method, data, authorization))
                number = int(url.split("/")[-2])
                return 200, {}, job.encode({"schema_version": 1, **IDENTITIES["child"],
                    "previous_batch": {"batchNumber": number - 1},
                    "batches": [{"stored": {"batchNumber": number}, "output": {}}]})
            return request(url, method, data, authorization, maximum)
        create = self.api.create
        def unique_create(request):
            retained = copy.deepcopy(self.api.pods)
            result = create(request)
            result["id"] = "pod_" + str(len(retained) + 1)
            self.api.pods = {**retained, result["id"]: copy.deepcopy(result)}
            return result
        workers = []
        with patch.object(self.native, "request", shared_queue), patch.object(self.api, "create", unique_create):
            for number in range(11):
                store = supervisor.initialize(self.root / ("worker-" + str(number)), selected)
                workers.append(supervisor.Supervisor(store, self.api, self.objects, self.native,
                    clock=lambda: self.now, controller_http=self.objects))
            for instance in workers[:10]:
                instance.tick()
            self.assertEqual(issued, list(range(12, 22)))
            self.assertEqual(len(queue), 90)
            for instance in workers[:10]:
                instance.tick()
                instance.tick()
            self.assertEqual(len(issued), 10)
            with self.assertRaisesRegex(runpod.Error, "concurrency_limit"):
                workers[10].tick()
            self.assertEqual(len(issued), 10)
            self.assertEqual(self.count("create"), 10)
            self.instance, self.store = workers[0], workers[0].store
            self.complete()
            self.instance.tick()
            self.assertEqual(issued[-1], 22)
            self.assertEqual(len(issued), 11)
            self.assertEqual(self.count("create"), 10)
            self.assertEqual(len(self.seen), 1)

    def test_dry_run_status_and_init_never_load_sdk_or_touch_network(self):
        config_path = self.root / "config.json"
        job.write_new(config_path, job.encode(self.config))
        with patch.object(supervisor.storage, "S3Storage", side_effect=AssertionError("SDK forbidden")), \
             patch.object(supervisor, "Runpod", side_effect=AssertionError("provider forbidden")), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(supervisor.main(["--state-dir", str(self.root / "planned"), "init", "--config", str(config_path)]), 0)
            self.assertEqual(supervisor.main(["--state-dir", str(self.store.root), "run", "--once"]), 0)
        self.assertFalse((self.root / "planned").exists())
        self.assertEqual(self.native.calls, [])

    def test_invalid_lease_or_url_lifetime_rejected_before_initialization(self):
        for change in (lambda c: c["sequencers"][0].update(native_lease_seconds=60),
                       lambda c: c["storage"].update(url_ttl_seconds=3600),
                       lambda c: c["runtime_seconds"].update(SNARK=3600)):
            config = copy.deepcopy(self.config)
            change(config)
            with self.assertRaises(runpod.Error):
                supervisor.load_config(config)

    def test_decentralized_service_mode_cannot_pull_native_jobs_or_copy_native_credentials(self):
        for config in ({**self.config, "mode": "decentralized-service"},
                       {**self.config, "mode": "decentralized-service", "external_pool_dirs": ["/private/pool"]},
                       {**self.config, "mode": "native-compute", "external_pool_dirs": ["/private/pool"]}):
            with self.subTest(mode=config["mode"]), self.assertRaisesRegex(runpod.Error, "requires_"):
                supervisor.load_config(config)


if __name__ == "__main__":
    unittest.main()
