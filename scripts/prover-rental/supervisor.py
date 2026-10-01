#!/usr/bin/env python3
"""One durable trusted-host scheduler per state directory; execution is opt-in."""

import argparse
import copy
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import time
import uuid

import job
import pool
import sentry
import storage
from runpod import (Controller, Error, Runpod, Store, TERMINAL, atomic_json, exact_fields,
                    positive_int, read_private_json, require)


MAX_JOBS_PER_SESSION = 128
MAX_EVIDENCE = 2 * 1024 * 1024
STALE_EXTERNAL_AUTHORIZATION = {
    "external_authorization_window_elapsed", "external_authorization_retired", "stale_wrapper_turn", "insufficient_compute_window",
    "compute_permit_state_changed", "compute_permit_checkpoint_changed", "frozen_package_repaired",
    "bootstrap_package_repaired", "bootstrap_phase_closed", "package_not_open", "roster_changed",
    "accepted_parent_changed", "native_proved_frontier_changed", "priority_work_not_frozen",
    "priority_checkpoint_needs_refresh",
}


def private_path(value):
    require(isinstance(value, str) and Path(value).is_absolute(), "absolute_private_path_required")
    return Path(value)


def load_config(config):
    exact_fields(config, ("schema_version", "mode", "provider_state_dir", "releases", "storage", "poll_interval_seconds",
                         "idle_grace_seconds", "startup_reserve_seconds", "runtime_seconds", "sequencers",
                         "external_pool_dirs"))
    require(config["schema_version"] == 1, "unsupported_supervisor_schema")
    require(config["mode"] in ("decentralized-service", "native-compute"), "invalid_supervisor_mode")
    if config["mode"] == "decentralized-service":
        require(config["sequencers"] == [] and config["external_pool_dirs"],
                "service_requires_assigned_external_work_without_native_credentials")
    else:
        require(config["external_pool_dirs"] == [] and config["sequencers"],
                "native_compute_requires_native_sources_without_service_pools")
    provider = Store(private_path(config["provider_state_dir"]))
    policy = provider.load()["policy"]
    storage.validate_config(config["storage"])
    for name in ("poll_interval_seconds", "idle_grace_seconds", "startup_reserve_seconds"):
        positive_int(config[name])
    require(config["poll_interval_seconds"] <= 60 and config["idle_grace_seconds"] <= 86400
            and config["startup_reserve_seconds"] <= 3600, "invalid_supervisor_interval")
    require(config["storage"]["url_ttl_seconds"] > policy["limits"]["max_runtime_seconds"]
            + 2 * config["startup_reserve_seconds"], "storage_urls_must_cover_session_and_recovery")
    exact_fields(config["releases"], ("FRI", "SNARK"))
    exact_fields(config["runtime_seconds"], ("FRI", "SNARK"))
    inputs, release_values = {"releases": {}, "auth": {}}, {}
    frozen = copy.deepcopy(config)
    for stage in ("FRI", "SNARK"):
        raw = job.read_file(private_path(config["releases"][stage]), job.MAX_MANIFEST)
        release = job.release_identity(raw)
        require(release["stage"] == stage, "supervisor_release_stage_mismatch")
        require(positive_int(config["runtime_seconds"][stage]) + config["startup_reserve_seconds"]
                < policy["limits"]["max_runtime_seconds"], "job_must_fit_warm_session")
        inputs["releases"][stage], release_values[stage] = raw, release
        frozen["releases"][stage] = job.hash_bytes(raw)
    for field in ("vk_hash", "program_commitment", "app_bin_sha256", "app_text_sha256"):
        require(release_values["FRI"][field] == release_values["SNARK"][field], "combined_release_identity_mismatch")
    require(isinstance(config["sequencers"], list) and len(config["sequencers"]) <= 32,
            "invalid_sequencer_inventory")
    names, endpoints = set(), set()
    for entry in frozen["sequencers"]:
        exact_fields(entry, ("name", "lane", "endpoint", "auth_file", "identity", "native_lease_seconds", "stages"))
        name = entry["name"]
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) and name not in names,
                "invalid_or_duplicate_sequencer_name")
        names.add(name)
        require(entry["lane"] in ("child", "gateway"), "invalid_settlement_lane")
        entry["endpoint"] = sentry.endpoint_url(entry["endpoint"])
        require(entry["endpoint"] not in endpoints, "duplicate_sequencer_endpoint")
        endpoints.add(entry["endpoint"])
        pool.validate_identity(entry["identity"])
        require(entry["identity"]["vk_hash"] == release_values["FRI"]["vk_hash"], "sequencer_release_identity_mismatch")
        require(isinstance(entry["stages"], list) and entry["stages"]
                and len(set(entry["stages"])) == len(entry["stages"])
                and all(stage in ("FRI", "SNARK") for stage in entry["stages"]), "invalid_sequencer_stages")
        require(60 <= positive_int(entry["native_lease_seconds"]) <= 86400, "invalid_native_lease_duration")
        require(all(config["runtime_seconds"][stage] + config["startup_reserve_seconds"]
                    < entry["native_lease_seconds"] for stage in entry["stages"]), "job_must_fit_native_lease")
        auth = job.read_file(private_path(entry["auth_file"]), 4096, private=True)
        sentry.authorization(entry["auth_file"])
        inputs["auth"][name] = auth
        entry["auth_sha256"] = job.hash_bytes(auth)
        del entry["auth_file"]
    require(isinstance(config["external_pool_dirs"], list) and len(config["external_pool_dirs"]) <= 32,
            "invalid_external_pool_inventory")
    require(len(set(config["external_pool_dirs"])) == len(config["external_pool_dirs"]), "duplicate_external_pool")
    for directory in config["external_pool_dirs"]:
        Store(private_path(directory))
    require(names or config["external_pool_dirs"], "at_least_one_work_source_required")
    frozen["provider_policy"] = policy
    return frozen, inputs


def initialize(root, config):
    settings, inputs = load_config(config)
    root = sentry.private_directory(root, create=True)
    for name in ("jobs", "releases", "auth", "expired", "retired"):
        sentry.private_directory(root / name, create=True)
    for stage, raw in inputs["releases"].items():
        job.write_new(root / "releases" / (stage + ".json"), raw)
    for name, raw in inputs["auth"].items():
        job.write_new(root / "auth" / (name + ".txt"), raw)
    atomic_json(root / "supervisor.json", {"schema_version": 1, "supervisor_id": uuid.uuid4().hex,
        "settings": settings, "active": None, "session": None, "cursor": 0, "idle_since": None,
        "last_tick_at": None, "last_error": None, "completed_jobs": 0, "draining": False})
    return Store(root)


class Supervisor:
    # Supervisor lock -> external pool lock -> provider lock. The watchdog takes
    # only provider locks, and no provider call attempts a reverse acquisition.
    def __init__(self, store, api=None, objects=None, native=None, clock=time.time, controller_http=None,
                 service_rpc=None, controller_type=Controller):
        self.store, self.api, self.clock = store, api, clock
        self.objects, self.native = objects, native or job.NativeNetwork()
        self.controller_http, self.service_rpc, self.controller_type = controller_http, service_rpc, controller_type
        self.state = read_private_json(store.root / "supervisor.json")
        require(self.state.get("schema_version") == 1, "unsupported_supervisor_state")
        self.settings = self.state["settings"]
        self.provider = Store(private_path(self.settings["provider_state_dir"]))
        require(self.provider.load()["policy"] == self.settings["provider_policy"], "provider_policy_changed")

    def save(self):
        atomic_json(self.store.root / "supervisor.json", self.state)

    def controller(self):
        return self.controller_type(self.provider, self.api, clock=self.clock, http=self.controller_http)

    def check_acquisition_capacity(self):
        with self.provider.lock():
            controller = self.controller()
            session = self.state["session"]
            if session is None:
                controller.check_session_capacity()
            else:
                controller.check_warm_job_capacity(session["operation"])

    def release(self, stage):
        raw = job.read_file(self.store.root / "releases" / (stage + ".json"), job.MAX_MANIFEST, private=True)
        require(job.hash_bytes(raw) == self.settings["releases"][stage], "frozen_release_changed")
        return raw

    def source(self, name):
        matches = [entry for entry in self.settings["sequencers"] if entry["name"] == name]
        require(len(matches) == 1, "unknown_sequencer")
        return matches[0]

    def auth(self, source):
        path = self.store.root / "auth" / (source["name"] + ".txt")
        require(job.hash_bytes(job.read_file(path, 4096, private=True)) == source["auth_sha256"], "frozen_auth_changed")
        return sentry.authorization(path)

    def directory(self, active=None):
        active = active or self.state["active"]
        if active["kind"] == "external":
            return Path(active["pool_dir"]) / active["lane"] / "jobs" / active["pool_operation"]
        return self.store.root / "jobs" / active["id"]

    def external_pool(self, active):
        return pool.Pool(Store(Path(active["pool_dir"])), clock=self.clock, service_rpc=self.service_rpc)

    def bind_native_evidence(self, active):
        directory = self.directory(active)
        source = self.source(active["source"])
        authority = read_private_json(directory / "authority.json")
        require(authority["endpoint"] == source["endpoint"] and authority["job_id"] == active["job_id"]
                and authority["release_sha256"] == self.settings["releases"][active["stage"]]
                and authority["stage"] == active["stage"], "native_authority_changed")
        if authority["status"] == "pick_uncertain":
            sentry.recover_pick(directory)
            authority = read_private_json(directory / "authority.json")
        require(authority["status"] == "picked", "native_pick_not_ready")
        if "expiry_not_before" not in active:
            # Recovery may first observe a completed response long after it arrived.
            # Starting the expiry bound here remains conservative across that crash.
            active["expiry_not_before"] = self.clock() + source["native_lease_seconds"]
            self.save()
        payload_raw = job.read_file(directory / "payload.json", job.MAX_PICK[active["stage"]], private=True)
        payload = job.validate_payload(job.decode(payload_raw), active["stage"], source["identity"]["vk_hash"])
        start = payload.get("batch_number", payload.get("from_batch_number"))
        end = payload.get("batch_number", payload.get("to_batch_number"))
        bounds = str(start) if active["stage"] == "FRI" else f"{start}/{end}"
        status, _, raw = self.native.request(source["endpoint"] + f"prover-jobs/v1/{active['stage']}/{bounds}/evidence",
                                             authorization=self.auth(source), maximum=MAX_EVIDENCE)
        require(status == 200, "native_evidence_unavailable_preserve_lease")
        evidence = job.decode(raw)
        exact_fields(evidence, ("schema_version", "chain_id", "chain_address", "settlement_chain_id",
                                "protocol_version", "vk_hash", "previous_batch", "batches"))
        require(evidence["schema_version"] == 1 and all(evidence[key] == value for key, value in source["identity"].items()),
                "native_evidence_identity_mismatch")
        require(start > 0 and evidence["previous_batch"]["batchNumber"] == start - 1
                and [entry["stored"]["batchNumber"] for entry in evidence["batches"]] == list(range(start, end + 1)),
                "native_evidence_range_mismatch")
        evidence_raw = job.encode(evidence)
        binding = job.validate_chain_binding({**source["identity"], "lane": source["lane"],
            "evidence_sha256": job.hash_bytes(evidence_raw), "payload_sha256": job.hash_bytes(payload_raw),
            "origin_endpoint_sha256": job.hash_bytes(source["endpoint"].encode())})
        require(authority.get("chain_binding") in (None, binding), "native_evidence_changed")
        retained = directory / "evidence.json"
        if retained.exists():
            require(job.read_file(retained, MAX_EVIDENCE, private=True) == evidence_raw, "native_evidence_changed")
        else:
            job.write_new(retained, evidence_raw)
        authority["chain_binding"] = binding
        atomic_json(directory / "authority.json", authority)
        active.update(phase="ready", chain_binding=binding)
        self.save()

    def pick_native(self, source, stage):
        identifier = uuid.uuid4().hex
        now = self.clock()
        active = {"id": identifier, "kind": "native", "source": source["name"], "stage": stage,
                  "job_id": self.state["supervisor_id"] + ":" + identifier, "phase": "pick_intent",
                  "picked_at": now, "deadline": now + source["native_lease_seconds"],
                  "runtime_seconds": self.settings["runtime_seconds"][stage], "plan": None,
                  "rental_operation": None, "chain_binding": None}
        self.state["active"] = active
        self.save()
        return self.recover_native_pick(active)

    def recover_native_pick(self, active):
        directory = self.directory(active)
        source = self.source(active["source"])
        if not os.path.lexists(directory / "authority.json"):
            release = self.release(active["stage"])
            sentry.reset_unstarted_pick(directory, source["endpoint"], release, active["job_id"])
            self.check_acquisition_capacity()
            # A pre-request crash may outlive the original compute window. Persist a new
            # bound only after proving that no native request could have happened yet.
            now = self.clock()
            active.update(picked_at=now, deadline=now + source["native_lease_seconds"])
            self.save()
            sentry.pick(directory, source["endpoint"], release, active["job_id"],
                        self.auth(source), self.native)
        authority = read_private_json(directory / "authority.json")
        if authority["status"] == "no_job":
            self.state["active"] = None
            self.save()
            # Marked-empty probes carry no lease or proof and need not accumulate
            # unbounded controller state during a quiet continuously running chain.
            for name in ("authority.json", "release.json"):
                (directory / name).unlink()
            directory.rmdir()
            return False
        self.bind_native_evidence(active)
        return True

    def claim_external(self, stage):
        for root in self.settings["external_pool_dirs"]:
            pool_store = Store(Path(root))
            with pool_store.lock("pool.lock"):
                candidate = pool.Pool(pool_store, clock=self.clock, service_rpc=self.service_rpc)
                for identifier, op in candidate.state["operations"].items():
                    if op["mode"] != "external" or op["stage"] != stage or op["status"] != "ready" or op.get("warm_owner"):
                        continue
                    lane = candidate.settings["lanes"][op["lane"]]
                    entry = lane["stages"][stage]
                    require(entry["release_sha256"] == self.settings["releases"][stage]
                            and entry["rental_policy"]["image"] == self.settings["provider_policy"]["image"],
                            "external_pool_release_or_image_mismatch")
                    runtime = entry["rental_policy"]["limits"]["max_runtime_seconds"]
                    require(runtime <= self.settings["runtime_seconds"][stage], "external_runtime_exceeds_supervisor_limit")
                    candidate.bound_authority(identifier)
                    require(stage != "SNARK" or entry.get("service") is not None, "external_snark_requires_service_configuration")
                    service = entry.get("service")
                    reserve = max(self.settings["startup_reserve_seconds"],
                                  service["policy"]["reserve_seconds"] if service is not None else 0)
                    if self.clock() + runtime + reserve >= op["deadline"]:
                        # A queued external payload owns no native capability. Do not let an
                        # unusable wrapper window block the next FRI opportunity.
                        with self.provider.lock():
                            self.require_unstarted_external(candidate, identifier)
                            self.mark_authorization_expired(op, "external_authorization_window_elapsed")
                            candidate.save()
                        continue
                    active = {"id": uuid.uuid4().hex, "kind": "external", "pool_dir": root,
                              "pool_operation": identifier, "lane": op["lane"], "stage": stage,
                              "job_id": op["job_id"], "phase": "claim_intent", "deadline": op["deadline"],
                              "runtime_seconds": runtime, "chain_binding": op["chain_binding"],
                              "plan": None, "rental_operation": None}
                    # Persist owner intent before the pool claim. Recovery finishes
                    # exactly this transition and never adopts another owner's job.
                    self.state["active"] = active
                    self.save()
                    op.update(status="warm_claimed", warm_owner=self.state["supervisor_id"],
                              warm_controller_dir=str(self.provider.root))
                    candidate.save()
                    active["phase"] = "ready"
                    self.save()
                    return True
        return False

    def require_unstarted_external(self, candidate, identifier, active=None):
        op = candidate.operation(identifier)
        require(op["mode"] == "external" and op.get("rental_operation") is None,
                "external_execution_requires_reconciliation")
        controllers = [self.controller(), Controller(candidate.controller_store(op), None, clock=self.clock)]
        require(not any(controller.has_job(op["job_id"]) for controller in controllers),
                "external_execution_requires_reconciliation")
        require(not (candidate.directory(identifier) / "returned-proof.json").exists(),
                "durable_result_requires_recovery")
        if active is not None:
            require(active["rental_operation"] is None and active["phase"] in ("claim_intent", "ready", "exported"),
                    "published_authority_requires_recovery")
            require(controllers[0].find_operation(active["id"]) is None
                    and not any((self.provider.root / filename).exists()
                                for filename in (active["id"] + ".proof", "." + active["id"] + ".partial")),
                    "durable_result_requires_recovery")

    def mark_authorization_expired(self, op, reason, release_reservation=True):
        if op["status"] != "authorization_expired":
            op.update(status="authorization_expired", authorization_expired_at=self.clock(),
                      authorization_expired_reason=reason)
            if release_reservation:
                op.update(released_reserved_usd=op["reserved_usd"], reserved_usd="0")

    def retire_unstarted_external(self, active, reason):
        require(active["kind"] == "external", "external_authority_required")
        self.recover_warm_attempt(active)
        if active["phase"] == "published":
            return False
        archive = self.store.root / "retired" / (active["id"] + ".json")
        with Store(Path(active["pool_dir"])).lock("pool.lock"):
            candidate = self.external_pool(active)
            op = candidate.operation(active["pool_operation"])
            if active["phase"] == "claim_intent" and op["status"] == "authorization_expired":
                # Another worker may retire an expired queued item after this host
                # persisted its claim intent but crashed before claiming the pool row.
                require(all(op[key] == active[key] for key in ("job_id", "lane", "stage", "chain_binding", "deadline")),
                        "external_claim_changed")
                candidate.bound_authority(active["pool_operation"])
            else:
                candidate, op = self.external_bound(active)
            require(op["status"] in ("warm_claimed", "authorization_expired"), "external_claim_changed")
            with self.provider.lock():
                self.require_unstarted_external(candidate, active["pool_operation"], active)
                session = self.state["session"]
                controller = self.controller()
                unallocated = session is None or (session["operation"] is None and not any(
                    entry.get("kind") == "warm_session"
                    and controller.operation(identifier)["session"] == session["descriptor"]
                    for identifier, entry in controller.state["operations"].items()))
                if archive.exists():
                    record = read_private_json(archive)
                    require(record["active"] == active and record["reason"] == reason,
                            "retired_authority_changed")
                else:
                    sentry.private_directory(archive.parent, create=not archive.parent.exists())
                    atomic_json(archive, {"schema_version": 1, "active": active,
                                         "retired_at": self.clock(), "reason": reason})
                # Even an unused newly allocated pod has reserved cost. Only release
                # the pool's conservative budget when no allocation could have begun.
                self.mark_authorization_expired(op, reason, release_reservation=unallocated)
                candidate.save()
                if unallocated:
                    self.state["session"] = None
        self.state["active"], self.state["idle_since"] = None, None
        self.save()
        return True

    def external_bound(self, active):
        candidate = self.external_pool(active)
        op = candidate.operation(active["pool_operation"])
        if active["phase"] == "claim_intent":
            require(op["status"] != "authorization_expired", "external_authorization_retired")
            require(op["status"] in ("ready", "warm_claimed")
                    and op.get("warm_owner") in (None, self.state["supervisor_id"]), "external_claim_conflict")
            op.update(status="warm_claimed", warm_owner=self.state["supervisor_id"],
                      warm_controller_dir=str(self.provider.root))
            candidate.save()
            active["phase"] = "ready"
            self.save()
        require(op.get("warm_owner") == self.state["supervisor_id"]
                and op.get("warm_controller_dir") == str(self.provider.root)
                and op["lane"] == active["lane"] and op["stage"] == active["stage"]
                and op["job_id"] == active["job_id"] and op["chain_binding"] == active["chain_binding"]
                and op["deadline"] == active["deadline"], "external_claim_changed")
        candidate.bound_authority(active["pool_operation"])
        return candidate, op

    def compute_window(self, active):
        deadline = active["deadline"]
        reserve = self.settings["startup_reserve_seconds"]
        if active["kind"] == "external":
            with Store(Path(active["pool_dir"])).lock("pool.lock"):
                candidate, op = self.external_bound(active)
                entry = candidate.settings["lanes"][active["lane"]]["stages"][active["stage"]]
                service = entry.get("service")
                reserve = max(reserve, service["policy"]["reserve_seconds"] if service is not None else 0)
                require(self.clock() + active["runtime_seconds"] + reserve < deadline,
                        "external_authorization_window_elapsed")
                if service is not None:
                    require(active["stage"] == "SNARK", "service_requires_external_snark")
                    keeper = pool.service_keeper()
                    raw = job.read_file(self.directory(active) / "compute-permit.json", 16 * 1024 * 1024, private=True)
                    require(job.hash_bytes(raw) == op.get("compute_permit_sha256"), "compute_permit_changed")
                    try:
                        checked = keeper.validate_permit(service, self.service_rpc or keeper.rpc_for(service), job.decode(raw),
                            job.decode(job.read_file(self.directory(active) / "evidence.json", MAX_EVIDENCE, private=True)),
                            job.decode(job.read_file(self.directory(active) / "payload.json", job.MAX_PICK["SNARK"], private=True)),
                            self.clock(), active["runtime_seconds"])
                    except keeper.s.Error as error:
                        raise Error(str(error)) from None
                    require(deadline <= checked["state"]["deadline"], "external_deadline_exceeds_compute_window")
                    reserve = max(reserve, service["policy"]["reserve_seconds"])
                    deadline = min(deadline, checked["state"]["deadline"])
        session = self.state["session"]
        if session is not None:
            deadline = min(deadline, session["deadline"], session["plan"]["expires_at"] - reserve)
        require(self.clock() + active["runtime_seconds"] + reserve < deadline, "insufficient_compute_window_preserve_job")
        return deadline, reserve

    def export(self, active):
        if active["plan"] is None:
            active["plan"] = self.objects.job_plan(active["id"])
            active["plan_expires_at"] = int(self.clock()) + self.settings["storage"]["url_ttl_seconds"]
            self.save()
        require(self.clock() + active["runtime_seconds"] + self.settings["startup_reserve_seconds"]
                < active["plan_expires_at"], "job_storage_urls_expired_preserve_job")
        upload = self.objects.job_transport(active["id"], active["plan"])
        if active["kind"] == "native":
            sentry.export(self.directory(active), active["plan"], upload)
        else:
            with Store(Path(active["pool_dir"])).lock("pool.lock"):
                self.external_bound(active)
                sentry.export_input(self.directory(active), job.read_file(self.directory(active) / "payload.json",
                    job.MAX_PICK[active["stage"]], private=True), self.release(active["stage"]), active["job_id"],
                    active["plan"], upload, active["chain_binding"])
        active["phase"] = "exported"
        self.save()

    def ensure_session(self, active):
        deadline, reserve = self.compute_window(active)
        if self.state["session"] is None:
            identifier = uuid.uuid4().hex
            plan = self.objects.session_plan(identifier)
            descriptor = {"schema_version": 1, "session_id": identifier, "mailbox_url": plan["mailbox_url"],
                          "finished_manifest_url": plan["finished_manifest_url"],
                          "finished_manifest_put_url": plan["finished_manifest_put_url"],
                          "session_key": secrets.token_hex(32),
                          "poll_interval_seconds": self.settings["poll_interval_seconds"]}
            now = self.clock()
            session = {"descriptor": descriptor, "plan": plan, "operation": None, "jobs": 0, "stopping": False,
                       "deadline": now + self.settings["provider_policy"]["limits"]["max_runtime_seconds"]}
            require(plan["expires_at"] > session["deadline"] + reserve, "session_storage_urls_too_short")
            self.state["session"] = session
            self.save()
        session = self.state["session"]
        with self.provider.lock():
            controller = self.controller()
            operation = controller.launch_session(session["descriptor"],
                latest_create_at=deadline - active["runtime_seconds"] - reserve)
            require(session["operation"] in (None, operation), "session_operation_changed")
            session["operation"] = operation
            self.save()
            op = controller.operation(operation)
            require(op["status"] not in TERMINAL, "warm_session_not_active_preserve_job")
            require(op["pod_id"] is not None and not op["cleanup_reason"], "warm_session_allocation_pending")

    def publish(self, active):
        deadline, _ = self.compute_window(active)
        session = self.state["session"]
        with self.provider.lock():
            controller = self.controller()
            selected = read_private_json(self.directory(active) / "controller-job.json")
            operation = controller.publish_warm_job(session["operation"], selected, active["stage"],
                attempt_id=active["id"], runtime_limit_seconds=active["runtime_seconds"], expires_at=int(deadline))
            require(active["rental_operation"] in (None, operation), "warm_job_operation_changed")
            active.update(phase="published", rental_operation=operation)
            self.save()
            import warm_protocol
            command = warm_protocol.encode(controller.warm_command(session["operation"]))
        self.objects.publish_command(session["descriptor"]["session_id"], command)

    def finish(self, active):
        with self.provider.lock():
            controller = self.controller()
            if not controller.collect(active["rental_operation"]):
                return False
        if active["kind"] == "native":
            disposition = sentry.submit(self.directory(active), self.provider, active["rental_operation"],
                                        self.auth(self.source(active["source"])), self.native)
        else:
            with Store(Path(active["pool_dir"])).lock("pool.lock"):
                candidate, op = self.external_bound(active)
                sentry.verify_input_result(self.directory(active), self.provider, active["rental_operation"],
                                           self.directory(active) / "returned-proof.json")
                op.update(status="returned", rental_operation=active["rental_operation"])
                candidate.save()
            disposition = "returned"
        with self.provider.lock():
            controller = self.controller()
            controller.finish_warm_job(active["rental_operation"], disposition)
        if active["kind"] == "native":
            source = self.source(active["source"])
            sentry.compact_native(self.directory(active), self.provider, active["rental_operation"],
                                  self.native_completion_expected(active["id"], active["stage"], source,
                                                                  active["chain_binding"]))
        self.state["session"]["jobs"] += 1
        self.state["completed_jobs"] += 1
        self.state["active"], self.state["idle_since"] = None, None
        self.save()
        return True

    def native_completion_expected(self, identifier, stage, source, binding):
        require(re.fullmatch(r"[0-9a-f]{32}", identifier) and stage in source["stages"],
                "native_completion_identity_changed")
        job.validate_chain_binding(binding)
        require(binding["lane"] == source["lane"]
                and binding["origin_endpoint_sha256"] == job.hash_bytes(source["endpoint"].encode())
                and all(binding[key] == value for key, value in source["identity"].items()),
                "native_completion_identity_changed")
        return {"job_id": self.state["supervisor_id"] + ":" + identifier, "stage": stage,
                "endpoint": source["endpoint"], "release_sha256": self.settings["releases"][stage],
                "chain_binding": binding}

    def compact_completed(self, execute=False):
        require(type(execute) is bool, "invalid_compaction_mode")
        completed, skipped = [], 0
        active = self.state["active"]
        for directory in sorted((self.store.root / "jobs").iterdir()):
            identifier = directory.name
            if (not re.fullmatch(r"[0-9a-f]{32}", identifier)
                    or active is not None and identifier == active["id"]
                    or any(os.path.lexists(self.store.root / kind / (identifier + ".json"))
                           for kind in ("expired", "retired"))):
                skipped += 1
                continue
            sentry.private_directory(directory)
            if not os.path.lexists(directory / "authority.json"):
                skipped += 1
                continue
            authority = sentry.native_completion_authority(directory)
            if (authority.get("job_id") != self.state["supervisor_id"] + ":" + identifier
                    or authority.get("status") not in ("accepted", "rejected")):
                skipped += 1
                continue
            sources = [entry for entry in self.settings["sequencers"] if entry["endpoint"] == authority["endpoint"]]
            require(len(sources) == 1, "native_completion_source_changed")
            expected = self.native_completion_expected(identifier, authority["stage"], sources[0],
                                                       authority["chain_binding"])
            present = {name for name in ("picked-wire.json", "payload.json", "evidence.json", "submission.json")
                       if os.path.lexists(directory / name)}
            record = sentry.compact_native(directory, self.provider, identifier, expected, execute=execute)
            completed.append({"operation_id": identifier, "disposition": authority["status"],
                              "intermediate_bytes": sum(record["files"][name]["bytes"] for name in present)})
        return {"action": "native_history_compacted" if execute else "plan_native_history_compaction",
                "jobs": completed, "skipped": skipped}

    def stop_session(self):
        session = self.state["session"]
        if session is None:
            return
        require(self.state["active"] is None, "pending_authority_prevents_idle_stop")
        with self.provider.lock():
            controller = self.controller()
            import warm_protocol
            command = warm_protocol.encode(controller.stop_session(session["operation"]))
        session["stopping"] = True
        self.save()
        self.objects.publish_command(session["descriptor"]["session_id"], command)

    def tick_session(self):
        session = self.state["session"]
        if session is None:
            return
        with self.provider.lock():
            controller = self.controller()
            if session["operation"] is None:
                matches = [identifier for identifier, op in controller.state["operations"].items()
                           if op.get("kind") == "warm_session"
                           and op["session"]["session_id"] == session["descriptor"]["session_id"]]
                require(len(matches) <= 1, "multiple_matching_warm_sessions")
                if not matches:
                    return
                session["operation"] = matches[0]
                require(controller.operation(matches[0])["session"] == session["descriptor"],
                        "session_configuration_changed")
                self.save()
            controller.tick(session["operation"])
            op = controller.operation(session["operation"])
            terminal = op["status"] in TERMINAL
        if terminal and self.state["active"] is None:
            self.state["session"], self.state["idle_since"] = None, None
            self.save()

    def expire_active(self):
        active = self.state["active"]
        require(active is not None, "no_active_job")
        self.tick_session()
        self.recover_warm_attempt(active)
        archive = self.store.root / "expired" / (active["id"] + ".json")
        retiring = archive.exists()
        if retiring:
            require(read_private_json(archive)["active"] == active, "expired_authority_changed")
        # A result wins over expiration, including an exact native submission that
        # was interrupted after the server accepted it but before local recording.
        if not retiring and active["phase"] == "published" and self.finish(active):
            return "completed"
        if active["kind"] == "native":
            authority = read_private_json(self.directory(active) / "authority.json")
            source = self.source(active["source"])
            require(authority["endpoint"] == source["endpoint"] and authority["job_id"] == active["job_id"]
                    and authority["stage"] == active["stage"]
                    and authority["release_sha256"] == self.settings["releases"][active["stage"]],
                    "native_authority_changed")
            require(authority["status"] == "picked" and authority["lease_token"] is not None
                    and not (self.directory(active) / "submission.json").exists(),
                    "unknown_pick_or_submission_requires_origin_reconciliation")
            require(active.get("expiry_not_before") is not None
                    and self.clock() >= active["expiry_not_before"], "native_lease_not_expired")
        else:
            with Store(Path(active["pool_dir"])).lock("pool.lock"):
                self.external_bound(active)
            require(self.clock() >= active["deadline"], "external_assignment_not_expired")
        session = self.state["session"]
        with self.provider.lock():
            controller = self.controller()
            if session is not None and session["operation"] is not None:
                require(controller.operation(session["operation"])["status"] in TERMINAL,
                        "provider_must_be_reconciled_and_stopped")
            retained_job = controller.find_operation(active["id"])
            if retained_job is not None:
                require(retained_job.get("kind") == "warm_job" and session is not None
                        and retained_job["session_operation_id"] == session["operation"], "warm_job_authority_changed")
                require(retiring or retained_job["receipt"] is None, "durable_result_requires_recovery")
            # Once retirement is chosen, a delayed storage response cannot change
            # the attempt's disposition during recovery of either journal.
            sentry.private_directory(archive.parent, create=not archive.parent.exists())
            if not retiring:
                atomic_json(archive, {"schema_version": 1, "active": active, "expired_at": self.clock()})
            if retained_job is not None:
                controller.finish_warm_job(active["id"], "failed")
        if active["kind"] == "external":
            with Store(Path(active["pool_dir"])).lock("pool.lock"):
                candidate, op = self.external_bound(active)
                require(op["status"] != "returned", "durable_result_requires_recovery")
                op["status"] = "lease_expired"
                candidate.save()
        self.state["active"], self.state["session"], self.state["idle_since"] = None, None, None
        self.save()
        return "expired"

    def recover_warm_attempt(self, active):
        if active["phase"] not in ("exported", "published"):
            return
        with self.provider.lock():
            op = self.controller().find_operation(active["id"])
            if op is None:
                require(active["phase"] != "published", "published_warm_job_missing")
                return
            session = self.state["session"]
            require(op.get("kind") == "warm_job" and session is not None
                    and op["session_operation_id"] == session["operation"]
                    and op["job"] == read_private_json(self.directory(active) / "controller-job.json")
                    and op["stage"] == active["stage"]
                    and op["command"]["body"]["runtime_limit_seconds"] == active["runtime_seconds"],
                    "warm_job_authority_changed")
        require(active["rental_operation"] in (None, active["id"]), "warm_job_operation_changed")
        active.update(phase="published", rental_operation=active["id"])
        self.save()

    def active_tick(self):
        active = self.state["active"]
        retired = self.store.root / "retired" / (active["id"] + ".json")
        if retired.exists():
            self.retire_unstarted_external(active, read_private_json(retired)["reason"])
            return
        if (self.store.root / "expired" / (active["id"] + ".json")).exists():
            self.expire_active()
            return
        self.recover_warm_attempt(active)
        if active["phase"] == "pick_intent":
            if not self.recover_native_pick(active):
                return
        try:
            if active["phase"] in ("ready", "claim_intent"):
                self.compute_window(active)
                self.export(active)
            if active["phase"] == "exported":
                self.ensure_session(active)
                self.publish(active)
        except Error as error:
            if active["kind"] == "external" and str(error) in STALE_EXTERNAL_AUTHORIZATION:
                if self.retire_unstarted_external(active, str(error)):
                    return
            raise
        if active["phase"] == "published":
            # A retained result or native submission remains recoverable even if
            # object-store writes fail after the worker has finished.
            if self.finish(active):
                return
            if active["kind"] == "external" and self.clock() >= active["deadline"]:
                with self.provider.lock():
                    stopped = self.controller().operation(self.state["session"]["operation"])["status"] in TERMINAL
                if stopped:
                    self.expire_active()
                    return
            # Retry the retained envelope after an ambiguous PUT; sequence/job IDs
            # make redelivery idempotent without issuing another lease or attempt.
            with self.provider.lock():
                controller = self.controller()
                import warm_protocol
                raw = warm_protocol.encode(controller.warm_command(self.state["session"]["operation"]))
            self.objects.publish_command(self.state["session"]["descriptor"]["session_id"], raw)

    def tick(self, acquire=True):
        try:
            self.tick_session()
            now = self.clock()
            if self.state["last_tick_at"] is not None:
                require(now >= self.state["last_tick_at"], "supervisor_clock_rollback")
            self.state["last_tick_at"], self.state["last_error"] = now, None
            if (self.store.root / "drain.json").exists():
                require(read_private_json(self.store.root / "drain.json") == {"schema_version": 1, "drain": True},
                        "invalid_drain_request")
                self.state["draining"] = True
            self.save()
            if self.state["active"] is not None:
                self.state["idle_since"] = None
                self.save()
                self.active_tick()
                return self.status()
            session = self.state["session"]
            if self.state["draining"]:
                if session is not None:
                    self.stop_session()
                return self.status()
            if session is not None and (session["stopping"] or session["jobs"] >= MAX_JOBS_PER_SESSION
                    or now + max(self.settings["runtime_seconds"].values()) + self.settings["startup_reserve_seconds"]
                    >= session["deadline"]):
                self.stop_session()
                return self.status()
            if not acquire:
                return self.status()
            self.check_acquisition_capacity()
            for stage in ("SNARK", "FRI"):
                if self.claim_external(stage):
                    self.state["idle_since"] = None
                    self.save()
                    self.active_tick()
                    return self.status()
                sources = [entry for entry in self.settings["sequencers"] if stage in entry["stages"]]
                for offset in range(len(sources)):
                    index = (self.state["cursor"] + offset) % len(sources)
                    if self.pick_native(sources[index], stage):
                        self.state["cursor"] = index + 1
                        self.state["idle_since"] = None
                        self.save()
                        self.active_tick()
                        return self.status()
            # Every configured native stage returned a marked empty response, and
            # every external pool was read successfully with no eligible job.
            if self.state["idle_since"] is None:
                self.state["idle_since"] = self.clock()
            self.save()
            if session is not None and self.clock() - self.state["idle_since"] >= self.settings["idle_grace_seconds"]:
                self.stop_session()
            return self.status()
        except (Error, OSError, ValueError, KeyError, TypeError) as error:
            self.state["idle_since"] = None
            self.state["last_error"] = str(error) if isinstance(error, Error) else "local_or_response_validation_failure"
            self.save()
            raise Error(self.state["last_error"]) from None

    def status(self):
        active, session = self.state["active"], self.state["session"]
        return {"schema_version": 1, "supervisor_id": self.state["supervisor_id"],
                "mode": self.settings["mode"],
                "active_job": None if active is None else {**{key: active[key]
                    for key in ("id", "kind", "stage", "phase", "deadline")},
                    "expiry_not_before": active.get("expiry_not_before")},
                "session_operation": None if session is None else session["operation"],
                "session_stopping": session is not None and session["stopping"],
                "completed_jobs": self.state["completed_jobs"], "idle_since": self.state["idle_since"],
                "draining": self.state["draining"], "last_error": self.state["last_error"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--state-dir", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--config", required=True, type=Path)
    run = commands.add_parser("run")
    run.add_argument("--once", action="store_true")
    commands.add_parser("status")
    commands.add_parser("recover")
    commands.add_parser("expire-active")
    commands.add_parser("compact-completed")
    commands.add_parser("drain")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            config = read_private_json(args.config)
            settings, _ = load_config(config)
            if args.execute:
                initialize(args.state_dir, config)
            print(job.encode({"action": "initialized" if args.execute else "plan_init", "state_dir": str(args.state_dir),
                              "mode": settings["mode"],
                              "sequencers": [entry["name"] for entry in settings["sequencers"]],
                              "external_pools": len(settings["external_pool_dirs"])}).decode())
            return 0
        store = Store(args.state_dir)
        if args.command == "drain":
            if args.execute:
                atomic_json(store.root / "drain.json", {"schema_version": 1, "drain": True})
            print(job.encode({"action": "drain_requested" if args.execute else "plan_drain"}).decode())
            return 0
        if args.command == "compact-completed" and not args.execute:
            print(job.encode(Supervisor(store).compact_completed()).decode())
            return 0
        with store.lock("supervisor.lock", blocking=False):
            supervisor = Supervisor(store)
            if args.command == "compact-completed":
                print(job.encode(supervisor.compact_completed(execute=args.execute)).decode())
                return 0
            if args.command == "status" or not args.execute:
                action = args.command if args.execute else "plan_expire_active" if args.command == "expire-active" else "dry_run"
                print(job.encode({"action": action, **supervisor.status()}).decode())
                return 0
            key = os.environ.get("RUNPOD_API_KEY", "")
            require(bool(key), "RUNPOD_API_KEY_required")
            supervisor.api = Runpod(key)
            supervisor.objects = storage.S3Storage(supervisor.settings["storage"])
            if args.command == "expire-active":
                action = supervisor.expire_active()
                print(job.encode({"action": action, **supervisor.status()}).decode())
                return 0
            stopping = False
            def stop(*_):
                nonlocal stopping
                stopping = True
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            while not stopping:
                try:
                    print(job.encode(supervisor.tick(acquire=args.command != "recover")).decode(), flush=True)
                except Error:
                    print(job.encode(supervisor.status()).decode(), flush=True)
                    if args.command == "recover" or args.once:
                        return 1
                if args.command == "recover" or args.once or supervisor.state["draining"] and supervisor.state["session"] is None:
                    break
                for _ in range(supervisor.settings["poll_interval_seconds"]):
                    if stopping:
                        break
                    time.sleep(1)
            return 0
    except (Error, OSError, ValueError, KeyError, TypeError):
        print('{"error":"supervisor_configuration_or_state_failure"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
