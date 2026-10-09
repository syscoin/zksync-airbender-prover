import argparse
import copy
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
import worker
from test_adapter import (RELEASE_WRITE_FAILURES, VK, Storage, interrupted_authority_directory_fsync,
                          interrupted_release_write, payload, release, storage_plan, successful_native)
from test_runpod import FakeApi, policy


IDENTITIES = {
    "child": {"chain_id": "0x23a", "chain_address": "0x" + "12" * 20,
              "settlement_chain_id": "0x13a", "protocol_version": 32, "vk_hash": VK},
    "gateway": {"chain_id": "0x13a", "chain_address": "0x" + "34" * 20,
                "settlement_chain_id": "0x1", "protocol_version": 32, "vk_hash": VK}}


def evidence(name, stage):
    end = 12 if stage == "FRI" else 13
    return {"schema_version": 1, **IDENTITIES[name], "previous_batch": {"batchNumber": 11},
            "batches": [{"stored": {"batchNumber": number}, "output": {}} for number in range(12, end + 1)]}


def registry_rpc_fixture(case, keeper, fixture):
    from test_keeper import RegistryRpc
    rpc = RegistryRpc(fixture["settings"], fixture["subscriptions"])
    connection = patch.object(keeper, "registry_rpc_for", return_value=rpc)
    connection.start()
    case.addCleanup(connection.stop)
    return rpc


class Native:
    def __init__(self):
        self.calls = []
        self.mismatch = False
        self.pick_error = False
        self.no_job = False
        self.submit_error = False

    def request(self, url, method="GET", data=None, authorization=None, maximum=None):
        self.calls.append((url, method, data, authorization))
        name = "child" if urllib.parse.urlsplit(url).port == 3125 else "gateway"
        stage = "FRI" if "/FRI/" in url else "SNARK"
        token = "0x" + ("f1" if name == "child" else "f2") * 32
        if "/pick?" in url:
            if self.pick_error:
                raise runpod.Error("transport_failure")
            return (204, {"x-syscoin-prover-pick-outcome": "unleased"}, b"") if self.no_job else (200, {}, job.encode({**payload(stage), "lease_token": token}))
        if url.endswith("/evidence"):
            return 200, {}, job.encode(evidence("gateway" if self.mismatch else name, stage))
        if "/submit?" in url:
            assert job.decode(data)["lease_token"] == token
            assert authorization.endswith("Y2hpbGQ6c2VjcmV0" if name == "child" else "Z2F0ZXdheTpzZWNyZXQ=")
            if self.submit_error:
                return 503, {}, b""
            return 204, {"x-syscoin-prover-disposition": "accepted"}, b""
        raise AssertionError("unexpected native call")


class PoolTests(unittest.TestCase):
    def require_service_tools(self):
        if "ZKSYNC_OS_SERVER_DIR" not in os.environ:
            self.skipTest("cross-repository service tests require ZKSYNC_OS_SERVER_DIR")
        return pool.service_keeper()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native, self.storage, self.api = Native(), Storage(), FakeApi()
        self.now = 1000

    def config(self, acquisition="native"):
        config = {"schema_version": 1, "limits": {"max_inflight_jobs": 4, "lifetime_budget_usd": "20"}, "lanes": {}}
        for index, name in enumerate(("child", "gateway")):
            secret = self.root / (name + "-auth.txt")
            job.write_new(secret, (name + ":secret").encode())
            stages = {}
            for stage in ("FRI", "SNARK"):
                release_path = self.root / (name + stage + "-release.json")
                policy_path = self.root / (name + stage + "-policy.json")
                job.write_new(release_path, job.encode(release(stage)))
                job.write_new(policy_path, job.encode(policy()))
                stages[stage] = {"acquisition": acquisition, "release_file": str(release_path),
                                 "rental_policy_file": str(policy_path), "service": None}
                if acquisition == "external" and stage == "SNARK":
                    keeper_config = {"schema_version": 1, "lane": name, "rpc_url": "http://127.0.0.1:8545",
                        "enrollment": {"registry_rpc_file": str(self.root / (name + "-registry-rpc.json")),
                                       "block_hash": "0x" + "64" * 32},
                        "settings": {"schema_version": 1, "execution_chain_id": IDENTITIES[name]["chain_id"],
                            "registry_chain_id": IDENTITIES["child"]["chain_id"], "chain_address": IDENTITIES[name]["chain_address"],
                            "settlement_chain_id": IDENTITIES[name]["settlement_chain_id"], "registry": "0x" + "56" * 20,
                            "coordinator": "0x" + "78" * 20, "proof_gate": "0x" + "90" * 20,
                            "policy_hash": "0x" + "ab" * 32, "vk_hash": VK, "sequencer": "0x" + "cd" * 20, "duties_per_round": 4},
                        "policy": {"expected_operator": "0x" + "ef" * 20, "gate_code_hash": "0x" + "11" * 32,
                            "coordinator_code_hash": "0x" + "22" * 32, "priority_guard_code_hash": "0x" + "33" * 32,
                            "reserve_seconds": 30, "max_head_age_seconds": 120, "rpc_timeout_seconds": 15}}
                    job.write_new(Path(keeper_config["enrollment"]["registry_rpc_file"]),
                                  job.encode({"url": "http://127.0.0.1:8546", "authorization": None}))
                    keeper_path = self.root / (name + "-keeper.json")
                    job.write_new(keeper_path, job.encode(keeper_config))
                    stages[stage]["service"] = {"keeper_config_file": str(keeper_path)}
            config["lanes"][name] = {"endpoint": f"http://127.0.0.1:{3125-index}/", "auth_file": str(secret) if acquisition == "native" else None,
                "identity": IDENTITIES[name], "limits": {"max_inflight_jobs": 2, "lifetime_budget_usd": "10"},
                "native_lease_seconds": 7200, "stages": stages}
        return config

    def start(self, acquisition="native", change=None):
        if acquisition == "external":
            self.require_service_tools()
        config = self.config(acquisition)
        if change:
            change(config)
        self.store = pool.initialize(self.root / "pool", config)
        return self.reload()

    def reload(self):
        self.instance = pool.Pool(self.store, self.native, self.storage, self.api,
                                  clock=lambda: self.now, controller_http=self.storage)
        return self.instance

    def compute(self, operation, finish=True):
        instance = self.instance
        op = instance.operation(operation)
        instance.export(operation, storage_plan())
        controller_store = instance.controller_store(op)
        controller_store.heartbeat(self.now)
        with controller_store.lock("watchdog.lock"):
            rental = instance.launch(operation)
        directory = instance.directory(operation)
        selected = runpod.read_private_json(directory / "controller-job.json")
        args = argparse.Namespace(operation_id=rental, job_id=selected["job_id"], manifest_url=selected["manifest_url"],
                                  manifest_sha256=selected["manifest_sha256"], runtime_limit_seconds=30)
        worker.execute(args, self.storage, successful_native(op["stage"]), directory / "release.json", verify=lambda _: None)
        if finish:
            return instance.complete(operation)
        return rental

    def test_native_round_robin_all_four_routes_return_to_origin_credentials_and_lease(self):
        instance = self.start()
        seen = []
        for expected in pool.ORDER:
            operation = instance.pick_next()
            op = instance.operation(operation)
            seen.append((op["lane"], op["stage"]))
            self.assertEqual(self.compute(operation), "complete")
            manifest = runpod.read_private_json(instance.directory(operation) / "manifest.json")
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["chain_binding"]["chain_id"], IDENTITIES[expected[0]]["chain_id"])
            for raw in self.storage.objects.values():
                self.assertNotIn(b"secret", raw)
                self.assertNotIn(b"lease_token", raw)
                self.assertNotIn(b"127.0.0.1", raw)
            instance = self.reload()
        self.assertEqual(seen, list(pool.ORDER))
        self.assertEqual(len([call for call in self.native.calls if "/pick?" in call[0]]), 4)
        self.assertEqual(len([call for call in self.api.calls if call[0] == "delete"]), 4)

    def test_legacy_launch_and_expiry_coexist_with_warm_session_history(self):
        from test_warm import session
        instance = self.start()
        operation = instance.pick_next()
        instance.export(operation, storage_plan())
        controller_store = instance.controller_store(instance.operation(operation))
        controller_store.heartbeat(self.now)
        with controller_store.lock("watchdog.lock"):
            controller = runpod.Controller(controller_store, self.api, clock=lambda: self.now)
            warm_operation = controller.launch_session(session())
            controller.terminate(warm_operation, failure=True)
            rental = instance.launch(operation)
        controller = runpod.Controller(controller_store, self.api, clock=lambda: self.now)
        controller.terminate(rental, failure=True)
        self.now = instance.operation(operation)["expiry_not_before"] + 1
        instance.expire(operation)
        self.assertEqual(instance.operation(operation)["status"], "lease_expired")
        self.assertEqual(len([call for call in self.api.calls if call[0] == "create"]), 2)

    def test_imported_dispatch_inputs_use_same_pool_without_native_pick_or_submit(self):
        instance = self.start("external")
        for name, stage in (("child", "FRI"), ("gateway", "FRI")):
            operation = instance.enqueue(name, stage, f"dispatch:{name}:{stage}:1", job.encode(payload(stage)),
                                         evidence(name, stage), 8200)
            self.assertEqual(self.compute(operation), "returned")
            directory = instance.directory(operation)
            self.assertTrue((directory / "returned-proof.json").exists())
            self.assertFalse((directory / "authority.json").exists())
            self.assertEqual(instance.operation(operation)["native_status"], "not_owned")
        self.assertEqual(self.native.calls, [])
        self.assertFalse((self.store.root / "child" / "auth.txt").exists())
        self.assertFalse((self.store.root / "gateway" / "auth.txt").exists())
        with self.assertRaisesRegex(runpod.Error, "no_pool_capacity_or_budget"):
            instance.pick_next()

    def test_identity_mismatch_blocks_export_and_keeps_native_reservation(self):
        instance = self.start(change=lambda config: config["limits"].update(max_inflight_jobs=1))
        self.native.mismatch = True
        with self.assertRaisesRegex(runpod.Error, "lane_evidence_identity_mismatch"):
            instance.pick_next()
        instance = self.reload()
        operation = next(iter(instance.state["operations"]))
        self.assertEqual(instance.operation(operation)["status"], "awaiting_evidence")
        with self.assertRaisesRegex(runpod.Error, "not_exportable"):
            instance.export(operation, storage_plan())
        with self.assertRaisesRegex(runpod.Error, "no_pool_capacity"):
            instance.pick_next()
        self.assertEqual(self.storage.puts, [])
        self.assertEqual(len([call for call in self.native.calls if "/pick?" in call[0]]), 1)

    def test_lost_native_pick_response_never_repeats_pick_or_expires_blindly(self):
        instance = self.start(change=lambda config: config["limits"].update(max_inflight_jobs=1))
        self.native.pick_error = True
        with self.assertRaisesRegex(runpod.Error, "transport_failure"):
            instance.pick_next()
        instance = self.reload()
        operation = next(iter(instance.state["operations"]))
        with self.assertRaisesRegex(runpod.Error, "no_pool_capacity"):
            instance.pick_next()
        self.now = 100000
        with self.assertRaisesRegex(runpod.Error, "requires_origin_reconciliation"):
            instance.expire(operation)
        self.assertEqual(len(self.native.calls), 1)

    def interrupted_pick(self):
        with patch("pool.sentry.pick", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.instance.pick_next()
        operation = next(reversed(self.instance.state["operations"]))
        return operation, copy.deepcopy(self.instance.operation(operation))

    def test_recover_unstarted_pick_preserves_identity_and_refreshes_only_proven_window(self):
        self.start()
        for index, shape in enumerate(("absent", "empty", "release", "temporary")):
            with self.subTest(shape=shape):
                operation, original = self.interrupted_pick()
                directory = self.instance.directory(operation)
                release_raw = job.read_file(self.store.root / original["lane"] / original["stage"] / "release.json", job.MAX_MANIFEST)
                if shape != "absent":
                    sentry.private_directory(directory, create=True)
                if shape == "release":
                    job.write_new(directory / "release.json", release_raw)
                if shape == "temporary":
                    _, authority = sentry.pick_intent(self.instance.settings["lanes"][original["lane"]]["endpoint"],
                                                     release_raw, original["job_id"])
                    job.write_new(directory / (".authority.json." + "a" * 32 + ".tmp"), job.encode(authority)[:40])
                self.now += 8000
                instance = self.reload()
                if index == 0:
                    with patch("pool.sentry.pick", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                        instance.recover_pick(operation)
                    retained = self.reload().operation(operation)
                    self.assertEqual((retained["picked_at"], retained["deadline"]), (self.now, self.now + 7200))
                    self.assertEqual(self.native.calls, [])
                    self.now += 8000
                instance = self.reload()
                instance.recover_pick(operation)
                op = instance.operation(operation)
                self.assertEqual((op["job_id"], op["reserved_usd"]), (original["job_id"], original["reserved_usd"]))
                self.assertEqual((op["picked_at"], op["deadline"], op["expiry_not_before"]),
                                 (self.now, self.now + 7200, self.now + 7200))
                self.assertEqual(op["status"], "ready")
                self.assertEqual(instance.state["cursor"], (index + 1) % len(pool.ORDER))
        self.assertEqual(len([call for call in self.native.calls if "/pick?" in call[0]]), 4)
        self.assertEqual(self.api.calls, [])

    def test_recover_missing_authority_rejects_capability_artifacts_and_owned_state(self):
        instance = self.start()
        operation, original = self.interrupted_pick()
        directory = sentry.private_directory(instance.directory(operation), create=True)
        wire = directory / "picked-wire.json"
        job.write_new(wire, job.encode({**payload("FRI"), "lease_token": "0x" + "f1" * 32}))
        self.now += 8000
        with self.assertRaisesRegex(runpod.Error, "pick_initialization_contains_unknown_artifacts"):
            self.reload().recover_pick(operation)
        self.assertEqual(wire.read_bytes(), job.encode({**payload("FRI"), "lease_token": "0x" + "f1" * 32}))
        self.assertEqual(self.reload().operation(operation), original)
        wire.unlink()
        instance = self.reload()
        instance.operation(operation)["lease_sha256"] = "a" * 64
        instance.save()
        owned = copy.deepcopy(instance.operation(operation))
        with self.assertRaisesRegex(runpod.Error, "missing_pick_authority_requires_origin_reconciliation"):
            self.reload().recover_pick(operation)
        self.assertEqual(self.reload().operation(operation), owned)
        self.assertEqual(self.native.calls, [])

    def test_release_initialization_failures_reuse_reserved_operation_and_persist_fresh_window_before_request(self):
        config = self.config()
        for window in RELEASE_WRITE_FAILURES:
            with self.subTest(window=window):
                self.store = pool.initialize(self.root / window, config)
                self.native = Native()
                self.reload()
                with interrupted_release_write(window), self.assertRaises(KeyboardInterrupt):
                    self.instance.pick_next()
                operation = next(iter(self.instance.state["operations"]))
                original = copy.deepcopy(self.instance.operation(operation))
                cursor = self.instance.state["cursor"]
                self.assertEqual(self.native.calls, [])
                self.assertFalse((self.instance.directory(operation) / "authority.json").exists())
                self.now += config["lanes"][original["lane"]]["native_lease_seconds"] + 1
                self.reload()
                request = self.native.request
                def checked_request(url, *args, **kwargs):
                    if "/pick?" in url:
                        state = runpod.read_private_json(self.store.root / "pool.json")
                        self.assertEqual(list(state["operations"]), [operation])
                        self.assertEqual(state["cursor"], cursor)
                        retained = state["operations"][operation]
                        for field in ("job_id", "reserved_usd", "lane", "stage"):
                            self.assertEqual(retained[field], original[field])
                        self.assertEqual((retained["picked_at"], retained["deadline"]), (self.now, self.now + 7200))
                        directory = self.instance.directory(operation)
                        self.assertEqual((directory / "release.json").read_bytes(), job.encode(release(original["stage"])))
                        self.assertEqual(runpod.read_private_json(directory / "authority.json")["status"], "pick_uncertain")
                    return request(url, *args, **kwargs)
                with patch.object(self.native, "request", side_effect=checked_request):
                    self.instance.recover_pick(operation)
                self.assertEqual(self.instance.operation(operation)["status"], "ready")
                self.assertEqual(self.instance.operation(operation)["reserved_usd"], original["reserved_usd"])
                self.assertEqual(len([call for call in self.native.calls if "/pick?" in call[0]]), 1)
                self.assertEqual(self.instance.state["cursor"], cursor)
                self.assertEqual(self.api.calls, [])

    def test_published_authority_fsync_failure_keeps_pool_window_and_reservation_blocked(self):
        self.start()
        with interrupted_authority_directory_fsync(), self.assertRaisesRegex(OSError, "authority directory fsync failed"):
            self.instance.pick_next()
        operation = next(iter(self.instance.state["operations"]))
        original = copy.deepcopy(self.instance.state)
        directory = self.instance.directory(operation)
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        self.assertEqual(set(before), {"release.json", "authority.json"})
        self.assertEqual(self.native.calls, [])
        self.now += 8000
        with self.assertRaises(FileNotFoundError):
            self.reload().recover_pick(operation)
        self.assertEqual(self.reload().state, original)
        self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.api.calls, [])

    def test_recover_existing_uncertain_authority_never_repicks_or_refreshes_window(self):
        instance = self.start()
        self.native.pick_error = True
        with self.assertRaisesRegex(runpod.Error, "transport_failure"):
            instance.pick_next()
        operation = next(iter(instance.state["operations"]))
        original = copy.deepcopy(instance.operation(operation))
        self.now += 8000
        self.native.pick_error = False
        with self.assertRaises(OSError):
            self.reload().recover_pick(operation)
        self.assertEqual(self.reload().operation(operation), original)
        self.assertEqual(len(self.native.calls), 1)

    def test_more_than_a_thousand_empty_polls_remain_bounded_and_rotate(self):
        instance = self.start()
        self.native.no_job = True
        previous, previous_directory = None, None
        for index in range(1005):
            instance = self.reload()
            operation = instance.pick_next()
            op = instance.operation(operation)
            self.assertEqual((op["lane"], op["stage"]), pool.ORDER[index % len(pool.ORDER)])
            self.assertEqual((op["status"], op["reserved_usd"], op["native_status"]), ("no_job", "0", "no_job"))
            self.assertEqual(list(instance.report()), [operation])
            self.assertEqual(runpod.read_private_json(instance.directory(operation) / "authority.json")["status"], "no_job")
            if previous is not None:
                self.assertNotIn(previous, instance.state["operations"])
                self.assertFalse(previous_directory.exists())
            previous, previous_directory = operation, instance.directory(operation)
        self.assertEqual(len(self.native.calls), 1005)
        self.assertTrue(all(instance.eligible(name, stage) for name, stage in pool.ORDER))
        self.assertEqual(self.api.calls, [])

    def legacy_empty(self, instance, operation, template):
        op = copy.deepcopy(template)
        op["job_id"] = instance.state["pool_id"] + ":" + op["lane"] + ":" + op["stage"] + ":" + operation
        instance.state["operations"][operation] = op
        directory = sentry.private_directory(instance.directory(operation), create=True)
        release_raw = job.read_file(self.store.root / op["lane"] / op["stage"] / "release.json", job.MAX_MANIFEST)
        _, authority = sentry.pick_intent(instance.settings["lanes"][op["lane"]]["endpoint"], release_raw, op["job_id"])
        authority["status"] = "no_job"
        runpod.atomic_json(directory / "authority.json", authority)
        job.write_new(directory / "release.json", release_raw)
        return op

    def test_full_legacy_empty_journal_recovers_before_operation_limit(self):
        instance = self.start()
        self.native.no_job = True
        first = instance.pick_next()
        template = copy.deepcopy(instance.operation(first))
        for index in range(999):
            self.legacy_empty(instance, f"{index:032x}", template)
        instance.save()
        self.assertEqual(len(instance.state["operations"]), 1000)
        instance = self.reload()
        operation = instance.pick_next()
        self.assertEqual(len(instance.state["operations"]), 1)
        self.assertEqual((instance.operation(operation)["lane"], instance.operation(operation)["stage"]), pool.ORDER[1])
        self.assertEqual(sum(len(list((self.store.root / name / "jobs").iterdir())) for name in ("child", "gateway")), 1)
        self.assertEqual(len(self.native.calls), 2)

    def test_empty_pruning_preserves_uncertain_spent_external_and_owned_records(self):
        instance = self.start()
        self.native.no_job = True
        first = instance.pick_next()
        template = copy.deepcopy(instance.operation(first))
        changes = [{"status": "pick_uncertain"}, {"reserved_usd": "2"}, {"mode": "external"},
                   {"lease_sha256": "a" * 64}, {"rental_operation": "rental"}, {"chain_binding": {"owned": True}},
                   {"warm_owner": "supervisor"}, {"native_status": None}, {"expiry_not_before": 8200},
                   {"released_reserved_usd": "2"}]
        retained = {}
        for index, change in enumerate(changes):
            operation = f"{index:032x}"
            op = self.legacy_empty(instance, operation, template)
            op.update(change)
            retained[operation] = copy.deepcopy(op)
        # A status-only row, a foreign artifact, and changed authority must never authorize deletion.
        for index, shape in enumerate(("missing", "artifact", "uncertain"), len(changes)):
            operation = f"{index:032x}"
            op = self.legacy_empty(instance, operation, template)
            directory = instance.directory(operation)
            if shape == "missing":
                (directory / "authority.json").unlink()
            elif shape == "artifact":
                job.write_new(directory / "picked-wire.json", b"retained capability")
            else:
                authority = runpod.read_private_json(directory / "authority.json")
                authority["status"] = "pick_uncertain"
                runpod.atomic_json(directory / "authority.json", authority)
            retained[operation] = copy.deepcopy(op)
        instance.save()
        before = {str(path): path.read_bytes() for name in ("child", "gateway")
                  for path in (self.store.root / name / "jobs").rglob("*") if path.is_file() and first not in str(path)}
        self.reload().prune_no_jobs()
        instance = self.reload()
        self.assertEqual(instance.state["operations"], retained)
        self.assertEqual(before, {str(path): path.read_bytes() for name in ("child", "gateway")
                         for path in (self.store.root / name / "jobs").rglob("*") if path.is_file()})
        self.assertEqual(sum(runpod.money(op["reserved_usd"], allow_zero=True) for op in retained.values()), 2)
        self.assertEqual(len(self.native.calls), 1)

    def interrupted_empty_cleanup(self, at_unlink):
        instance = self.start()
        self.native.no_job = True
        previous = instance.pick_next()
        directory = instance.directory(previous)
        original_unlink, original_save = Path.unlink, pool.Pool.save
        def unlink(path, *args, **kwargs):
            original_unlink(path, *args, **kwargs)
            if at_unlink and path.name == "authority.json":
                raise KeyboardInterrupt
        def save(selected):
            if not at_unlink and previous not in selected.state["operations"]:
                raise KeyboardInterrupt
            original_save(selected)
        with patch.object(Path, "unlink", unlink), patch.object(pool.Pool, "save", save), self.assertRaises(KeyboardInterrupt):
            instance.pick_next()
        instance = self.reload()
        self.assertIs(instance.operation(previous)["prune_no_job"], True)
        operation = instance.pick_next()
        self.assertNotIn(previous, instance.state["operations"])
        self.assertFalse(directory.exists())
        self.assertEqual((instance.operation(operation)["lane"], instance.operation(operation)["stage"]), pool.ORDER[1])
        self.assertEqual(instance.operation(operation)["reserved_usd"], "0")
        self.assertEqual(len(self.native.calls), 2)

    def test_empty_cleanup_recovers_after_partial_file_removal(self):
        self.interrupted_empty_cleanup(True)

    def test_empty_cleanup_recovers_after_file_removal_before_journal_retirement(self):
        self.interrupted_empty_cleanup(False)

    def test_empty_cleanup_resyncs_parent_after_directory_removal_interruption(self):
        instance = self.start()
        self.native.no_job = True
        previous = instance.pick_next()
        directory = instance.directory(previous)
        def interrupt_parent(path):
            if path == directory.parent:
                raise KeyboardInterrupt
            runpod.sync_dir(path)
        with patch("pool.sync_dir", interrupt_parent), self.assertRaises(KeyboardInterrupt):
            instance.pick_next()
        self.assertFalse(directory.exists())
        instance = self.reload()
        self.assertIs(instance.operation(previous)["prune_no_job"], True)
        original_save, synced = pool.Pool.save, []
        def sync(path):
            synced.append(path)
            runpod.sync_dir(path)
        def save(selected):
            if previous not in selected.state["operations"]:
                self.assertIn(directory.parent, synced)
            original_save(selected)
        with patch("pool.sync_dir", sync), patch.object(pool.Pool, "save", save):
            operation = instance.pick_next()
        self.assertEqual(list(instance.state["operations"]), [operation])
        self.assertEqual(len(self.native.calls), 2)

    def test_empty_cleanup_resyncs_visible_marker_before_removing_evidence(self):
        instance = self.start()
        self.native.no_job = True
        previous = instance.pick_next()
        directory = instance.directory(previous)
        original_sync, original_unlink = runpod.sync_dir, Path.unlink
        def interrupt_marker(path):
            if path == self.store.root:
                raise KeyboardInterrupt
            original_sync(path)
        with patch("runpod.sync_dir", interrupt_marker), self.assertRaises(KeyboardInterrupt):
            instance.pick_next()
        instance = self.reload()
        self.assertIs(instance.operation(previous)["prune_no_job"], True)
        self.assertTrue((directory / "authority.json").exists())
        synced = []
        def sync(path):
            synced.append(path)
            original_sync(path)
        def unlink(path, *args, **kwargs):
            if path.parent == directory:
                self.assertIn(self.store.root, synced)
            original_unlink(path, *args, **kwargs)
        with patch("runpod.sync_dir", sync), patch.object(Path, "unlink", unlink):
            operation = instance.pick_next()
        self.assertEqual(list(instance.state["operations"]), [operation])
        self.assertEqual(len(self.native.calls), 2)

    def test_empty_cleanup_persists_in_memory_marker_after_failed_save(self):
        instance = self.start()
        self.native.no_job = True
        previous = instance.pick_next()
        directory = instance.directory(previous)
        with patch("pool.atomic_json", side_effect=OSError("save failed")), self.assertRaises(OSError):
            instance.pick_next()
        self.assertIs(instance.operation(previous)["prune_no_job"], True)
        self.assertNotIn("prune_no_job", self.reload().operation(previous))
        original_unlink = Path.unlink
        def unlink(path, *args, **kwargs):
            if path.parent == directory:
                self.assertIs(self.reload().operation(previous)["prune_no_job"], True)
            original_unlink(path, *args, **kwargs)
        with patch.object(Path, "unlink", unlink):
            operation = instance.pick_next()
        self.assertEqual(list(instance.state["operations"]), [operation])
        self.assertEqual(len(self.native.calls), 2)

    def test_enqueue_prunes_only_prior_empty_native_probes(self):
        instance = self.start(change=lambda value: value["lanes"]["child"]["stages"]["FRI"].update(acquisition="external"))
        self.native.no_job = True
        previous = instance.pick_next()
        operation = instance.enqueue("child", "FRI", "dispatch:1", job.encode(payload("FRI")), evidence("child", "FRI"), 8200)
        self.assertEqual(list(instance.state["operations"]), [operation])
        self.assertEqual((instance.operation(operation)["mode"], instance.operation(operation)["reserved_usd"]), ("external", "2"))
        self.assertFalse((self.store.root / "gateway" / "jobs" / previous).exists())
        self.assertEqual(len(self.native.calls), 1)

    def test_no_jobs_release_reservations_and_rotate_lanes(self):
        instance = self.start()
        self.native.no_job = True
        for name, stage in pool.ORDER:
            operation = instance.pick_next()
            op = instance.operation(operation)
            self.assertEqual((op["lane"], op["stage"], op["status"], op["reserved_usd"]), (name, stage, "no_job", "0"))

    def test_shared_and_lane_budgets_are_permanent_after_success(self):
        instance = self.start(change=lambda config: config["limits"].update(lifetime_budget_usd="2"))
        self.compute(instance.pick_next())
        with self.assertRaisesRegex(runpod.Error, "no_pool_capacity_or_budget"):
            self.reload().pick_next()
        self.assertEqual(len([call for call in self.api.calls if call[0] == "create"]), 1)

    def test_enqueue_idempotency_and_cross_lane_swaps_fail_before_compute(self):
        instance = self.start("external")
        operation = instance.enqueue("child", "FRI", "shared-attempt", job.encode(payload("FRI")), evidence("child", "FRI"), 8200)
        self.assertEqual(self.reload().enqueue("child", "FRI", "shared-attempt", job.encode(payload("FRI")), evidence("child", "FRI"), 8200), operation)
        with self.assertRaisesRegex(runpod.Error, "external_job_identity_changed"):
            instance.enqueue("gateway", "FRI", "shared-attempt", job.encode(payload("FRI")), evidence("gateway", "FRI"), 8200)
        with self.assertRaisesRegex(runpod.Error, "lane_evidence_identity_mismatch"):
            instance.enqueue("gateway", "FRI", "other-attempt", job.encode(payload("FRI")), evidence("child", "FRI"), 8200)
        with self.assertRaisesRegex(runpod.Error, "invalid_fields"):
            instance.enqueue("child", "FRI", "leased", job.encode({**payload("FRI"), "lease_token": "0x" + "11" * 32}), evidence("child", "FRI"), 8200)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.native.calls, [])

    def test_authority_origin_and_auth_file_changes_rejected(self):
        instance = self.start()
        operation = instance.pick_next()
        directory = instance.directory(operation)
        authority = runpod.read_private_json(directory / "authority.json")
        authority["endpoint"] = "http://127.0.0.1:3124/"
        runpod.atomic_json(directory / "authority.json", authority)
        with self.assertRaisesRegex(runpod.Error, "native_origin_changed"):
            instance.export(operation, storage_plan())
        (self.store.root / "gateway" / "auth.txt").write_text("changed:password")
        with self.assertRaisesRegex(runpod.Error, "lane_credentials_changed"):
            instance.auth("gateway")

    def test_original_native_lease_and_range_cannot_be_replaced(self):
        instance = self.start()
        operation = instance.pick_next()
        path = instance.directory(operation) / "authority.json"
        authority = runpod.read_private_json(path)
        original = copy.deepcopy(authority)
        authority["lease_token"] = "0x" + "f2" * 32
        runpod.atomic_json(path, authority)
        with self.assertRaisesRegex(runpod.Error, "native_lease_changed"):
            instance.export(operation, storage_plan())
        original["bounds"]["batch_number"] += 1
        runpod.atomic_json(path, original)
        with self.assertRaisesRegex(runpod.Error, "native_bounds_changed"):
            instance.export(operation, storage_plan())

    def test_external_admission_enforces_shared_slots_and_each_lane_cap(self):
        instance = self.start("external", change=lambda config: config["limits"].update(max_inflight_jobs=2))
        instance.enqueue("child", "FRI", "child-fri", job.encode(payload("FRI")), evidence("child", "FRI"), 8200)
        instance.enqueue("gateway", "FRI", "gateway-fri", job.encode(payload("FRI")), evidence("gateway", "FRI"), 8200)
        with self.assertRaisesRegex(runpod.Error, "no_pool_capacity_or_budget"):
            instance.enqueue("child", "SNARK", "child-snark", job.encode(payload("SNARK")), evidence("child", "SNARK"), 8200, {})
        self.assertEqual(len(instance.state["operations"]), 2)
        self.assertEqual(self.native.calls, [])

    def test_native_transport_accepts_only_https_or_loopback_without_url_credentials(self):
        for url in ("https://trusted.example/", "http://127.0.0.1:3124/", "http://[::1]:3125/"):
            self.assertEqual(job.native_url(url), url)
        for url in ("http://trusted.example:3124/", "http://user:pass@127.0.0.1:3124/", "http://127.0.0.1:3124/#secret"):
            with self.assertRaises(runpod.Error):
                job.native_url(url)
        with self.assertRaisesRegex(runpod.Error, "duplicate_json_field"):
            job.decode(b'{"chain_id":"0x1","chain_id":"0x2"}')

    def test_lost_native_submission_retries_same_original_wire(self):
        instance = self.start()
        operation = instance.pick_next()
        self.compute(operation, finish=False)
        self.native.submit_error = True
        with self.assertRaisesRegex(runpod.Error, "submission_retained"):
            instance.complete(operation)
        original = self.native.calls[-1]
        self.native.submit_error = False
        self.assertEqual(self.reload().complete(operation), "complete")
        self.assertEqual(self.native.calls[-1], original)

    def test_lost_pool_launch_ack_recovers_existing_allocation_even_past_deadline(self):
        instance = self.start()
        operation = instance.pick_next()
        instance.export(operation, storage_plan())
        controller_store = instance.controller_store(instance.operation(operation))
        controller_store.heartbeat(self.now)
        with controller_store.lock("watchdog.lock"):
            rental = instance.launch(operation)
        instance.operation(operation).update(status="exported", rental_operation=None)
        instance.save()
        self.now = 9000
        self.assertEqual(self.reload().launch(operation), rental)
        self.assertEqual(len([call for call in self.api.calls if call[0] == "create"]), 1)

    def test_chain_binding_payload_hash_is_checked_by_rental_worker(self):
        instance = self.start()
        operation = instance.pick_next()
        instance.export(operation, storage_plan())
        directory = instance.directory(operation)
        manifest = runpod.read_private_json(directory / "manifest.json")
        manifest["chain_binding"]["payload_sha256"] = "e" * 64
        with self.assertRaisesRegex(runpod.Error, "manifest_chain_binding_mismatch"):
            worker.validate_manifest(manifest, release("FRI"), job.hash_bytes(job.encode(release("FRI"))), instance.operation(operation)["job_id"])

    def service_job(self):
        keeper = self.require_service_tools()
        from test_keeper import NativeRpc, setup
        from test_service import fixture
        f = fixture()
        config, request, item = setup(f)
        self.service_config, self.service_fixture = config, f
        self.service_rpc = NativeRpc(f, config, item)
        self.service_registry_rpc = registry_rpc_fixture(self, keeper, f)
        permit = keeper.permit(config, self.service_rpc, request, f["evidence"], f["fri_payload"], self.now, 50)
        self.assertTrue(self.service_registry_rpc.anchors)
        self.assertEqual(set(self.service_registry_rpc.anchors), {config["enrollment"]["block_hash"]})
        pool_config = self.config("external")
        lane = pool_config["lanes"]["child"]
        lane["identity"] = {key: f["evidence"][key] for key in IDENTITIES["child"]}
        for stage in ("FRI", "SNARK"):
            entry = lane["stages"][stage]
            selected_release = release(stage)
            selected_release["vk_hash"] = config["settings"]["vk_hash"]
            runpod.atomic_json(Path(entry["release_file"]), selected_release)
            selected_policy = policy()
            selected_policy["limits"]["max_runtime_seconds"] = 50
            runpod.atomic_json(Path(entry["rental_policy_file"]), selected_policy)
        runpod.atomic_json(Path(lane["stages"]["SNARK"]["service"]["keeper_config_file"]), config)
        self.store = pool.initialize(self.root / "pool", pool_config)
        instance = self.reload()
        instance.service_rpc = self.service_rpc
        operation = instance.enqueue("child", "SNARK", "selected-wrapper:1", job.encode(f["fri_payload"]),
                                     f["evidence"], 1200, permit)
        instance.export(operation, storage_plan())
        controller_store = instance.controller_store(instance.operation(operation))
        controller_store.heartbeat(self.now)
        watchdog = controller_store.lock("watchdog.lock")
        watchdog.__enter__()
        self.addCleanup(watchdog.__exit__, None, None, None)
        return instance, operation

    def test_external_snark_rejects_missing_or_null_service_configuration(self):
        config = self.config("external")
        entry = config["lanes"]["child"]["stages"]["SNARK"]
        entry["service"] = None
        with self.assertRaisesRegex(runpod.Error, "external_snark_requires_service_configuration"):
            pool.load_config(config)
        del entry["service"]
        with self.assertRaisesRegex(runpod.Error, "invalid_fields"):
            pool.load_config(config)

    def test_service_wrong_turn_or_repaired_package_never_creates_pod(self):
        instance, operation = self.service_job()
        self.service_rpc.turn += 1
        with self.assertRaisesRegex(runpod.Error, "stale_wrapper_turn"):
            instance.launch(operation)
        self.service_rpc.turn -= 1
        self.service_rpc.frozen_override = "0x" + "fe" * 32
        with self.assertRaisesRegex(runpod.Error, "frozen_package_repaired"):
            instance.launch(operation)
        self.assertEqual(self.api.calls, [])

    def test_service_ineligible_enrollment_fails_before_paid_compute(self):
        instance, operation = self.service_job()
        self.service_registry_rpc.ineligible.add(self.service_fixture["subscription"]["account"])
        with self.assertRaisesRegex(runpod.Error, "subscription_snapshot_omits_or_adds_eligible_accounts"):
            instance.launch(operation)
        self.assertEqual(self.api.calls, [])

    def test_service_permit_payload_is_immutable_and_duplicate_launch_is_recovered(self):
        instance, operation = self.service_job()
        original = instance.launch(operation)
        self.now = 1500
        self.service_rpc.turn += 100
        self.assertEqual(instance.launch(operation), original)
        self.assertEqual(len([call for call in self.api.calls if call[0] == "create"]), 1)
        manifest = runpod.read_private_json(instance.directory(operation) / "manifest.json")
        self.assertNotIn("compute_permit", manifest)
        self.assertNotIn("expected_operator", manifest)
        self.assertEqual(manifest["chain_binding"], instance.operation(operation)["chain_binding"])

    def test_service_preflight_elapsed_wall_clock_prevents_paid_create(self):
        instance, operation = self.service_job()
        original = self.service_rpc.call

        def slow(method, params):
            result = original(method, params)
            if method == "eth_getBlockByNumber" and params[0] != "latest":
                self.now = 1130
            return result

        self.service_rpc.call = slow
        with self.assertRaisesRegex(runpod.Error, "compute_window_elapsed_during_validation"):
            instance.launch(operation)
        self.assertEqual(self.api.calls, [])

    def test_service_catalog_latency_rechecks_deadline_before_provider_post(self):
        instance, operation = self.service_job()
        original = self.api.catalog

        def slow(gpu):
            result = original(gpu)
            self.now = 1130
            return result

        self.api.catalog = slow
        with self.assertRaisesRegex(runpod.Error, "compute_window_elapsed_before_create"):
            instance.launch(operation)
        self.assertFalse(any(call[0] == "create" for call in self.api.calls))

    def test_service_missing_permit_and_tampered_file_fail_before_launch(self):
        instance, operation = self.service_job()
        with self.assertRaisesRegex(runpod.Error, "service_compute_permit_required"):
            instance.enqueue("child", "SNARK", "missing", job.encode(self.service_fixture["fri_payload"]),
                             self.service_fixture["evidence"], 1200)
        path = instance.directory(operation) / "compute-permit.json"
        value = runpod.read_private_json(path)
        value["request"]["proposal"]["accepted_package"]["batchTo"] += 1
        runpod.atomic_json(path, value)
        with self.assertRaisesRegex(runpod.Error, "compute_permit_changed"):
            instance.launch(operation)
        self.assertEqual(self.api.calls, [])


if __name__ == "__main__":
    unittest.main()
