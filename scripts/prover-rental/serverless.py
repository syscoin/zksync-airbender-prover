#!/usr/bin/env python3
"""Trusted, bounded FRI submission to an existing Runpod Serverless endpoint."""

import argparse
from decimal import Decimal
import hashlib
import math
import os
from pathlib import Path
import re
import sys
import time
import uuid

import job
from runpod import (Error, Http, HttpError, Store, atomic_json, check_artifact, exact_fields,
                    https_url, money, positive_int, private_open, read_private_json, require,
                    sha256, sync_dir, validate_job)


BACKEND = "runpod-serverless-fri"
FINAL = {"accepted", "rejected", "returned", "expired"}
PROVIDER_FINAL = {"COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"}
OP_FIELDS = ("backend", "controller_id", "job", "input", "created_at", "deadline", "reserved_usd",
             "provider_job_id", "provider_status", "status", "receipt", "disposition", "last_error")


def timestamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value < 1e12,
            "invalid_serverless_timestamp")
    return value


def lifetime_bound(evidence):
    return (evidence["anchor_at"] + (evidence["ttl_ms"] + evidence["execution_timeout_ms"]) / 1000
            + evidence["cleanup_allowance_seconds"])


def provider_resolved(operation):
    # ABSENT alone is never final. This separate local closure retains the actual
    # 404 observation, not a fabricated Runpod COMPLETED/TIMED_OUT response.
    evidence = operation.get("provider_lifetime")
    return operation["provider_status"] in PROVIDER_FINAL or (
        operation["provider_status"] == "ABSENT" and evidence is not None and evidence["closed_at"] is not None)


def validate_lifetime(operation, policy):
    evidence = operation.get("provider_lifetime")
    if "provider_lifetime" not in operation:
        return
    exact_fields(evidence, ("basis", "endpoint_id", "provider_job_id", "anchor_at", "ttl_ms",
                            "execution_timeout_ms", "cleanup_allowance_seconds", "closed_at", "contradicted_at"))
    require(evidence["basis"] in ("submit_ack", "legacy_observation")
            and evidence["endpoint_id"] == policy["endpoint_id"]
            and operation["provider_job_id"] is not None
            and evidence["provider_job_id"] == operation["provider_job_id"], "serverless_lifetime_identity_changed")
    require(timestamp(evidence["anchor_at"]) >= operation["created_at"], "serverless_lifetime_clock_rollback")
    # New records bind the exact request; legacy records conservatively wait
    # from a fresh observation using maximum policy bounds, not an invented ACK.
    runtime = (int(operation["deadline"] - operation["created_at"]) if evidence["basis"] == "submit_ack"
               else policy["limits"]["max_runtime_seconds"])
    require(0 < runtime <= policy["limits"]["max_runtime_seconds"]
            and type(evidence["execution_timeout_ms"]) is int and evidence["execution_timeout_ms"] == runtime * 1000
            and type(evidence["ttl_ms"]) is int
            and evidence["ttl_ms"] == (runtime + policy["limits"]["result_retention_seconds"]) * 1000
            and type(evidence["cleanup_allowance_seconds"]) is int
            and evidence["cleanup_allowance_seconds"] == policy["limits"]["startup_timeout_seconds"]
                + 10 + policy["idle_timeout_seconds"], "serverless_lifetime_bounds_changed")
    if evidence["closed_at"] is not None:
        require(timestamp(evidence["closed_at"]) >= lifetime_bound(evidence)
                and evidence["contradicted_at"] is None
                and operation["provider_status"] == "ABSENT", "invalid_serverless_lifetime_closure")
    if evidence["contradicted_at"] is not None:
        require(timestamp(evidence["contradicted_at"]) >= lifetime_bound(evidence),
                "invalid_serverless_lifetime_counterevidence")


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value), "invalid_serverless_identifier")
    return value


def attempt(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value), "invalid_serverless_attempt")
    return value


def validate_policy(policy):
    exact_fields(policy, ("schema_version", "endpoint_id", "template_id", "image", "gpu_type_ids", "gpu_pools",
                          "allowed_cuda_versions", "min_cuda_version", "gpu_count", "workers_min", "workers_max",
                          "flashboot", "idle_timeout_seconds", "disk_gb", "limits"))
    require(policy["schema_version"] == 1, "unsupported_serverless_policy")
    identifier(policy["endpoint_id"])
    identifier(policy["template_id"])
    require(isinstance(policy["image"], str) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", policy["image"]), "image_requires_digest")
    require(isinstance(policy["gpu_type_ids"], list) and len(policy["gpu_type_ids"]) == 1
            and isinstance(policy["gpu_type_ids"][0], str) and 0 < len(policy["gpu_type_ids"][0]) <= 128,
            "one_exact_serverless_gpu_type_required")
    require(isinstance(policy["gpu_pools"], list) and len(policy["gpu_pools"]) == 1
            and isinstance(policy["gpu_pools"][0], str)
            and re.fullmatch(r"[A-Z0-9_]{1,64}", policy["gpu_pools"][0]), "one_serverless_gpu_pool_required")
    require(isinstance(policy["allowed_cuda_versions"], list)
            and len(policy["allowed_cuda_versions"]) <= 16
            and len(set(policy["allowed_cuda_versions"])) == len(policy["allowed_cuda_versions"])
            and all(isinstance(v, str) and re.fullmatch(r"\d+\.\d+", v)
                    for v in policy["allowed_cuda_versions"]), "invalid_serverless_cuda_versions")
    require((policy["allowed_cuda_versions"] and policy["min_cuda_version"] is None)
            or not policy["allowed_cuda_versions"] and isinstance(policy["min_cuda_version"], str)
            and re.fullmatch(r"\d+\.\d+", policy["min_cuda_version"]), "mutually_exclusive_cuda_selection_required")
    positive_int(policy["disk_gb"])
    require(type(policy["gpu_count"]) is int and policy["gpu_count"] == 1
            and type(policy["workers_min"]) is int and policy["workers_min"] == 0
            and type(policy["workers_max"]) is int and policy["workers_max"] == 1
            and policy["flashboot"] is True, "serverless_requires_flashboot_and_one_scale_to_zero_worker")
    require(1 <= positive_int(policy["idle_timeout_seconds"]) <= 60, "invalid_serverless_idle_timeout")
    limits = policy["limits"]
    exact_fields(limits, ("max_runtime_seconds", "startup_timeout_seconds", "result_retention_seconds",
                          "max_hourly_usd", "max_operation_usd", "lifetime_budget_usd",
                          "max_artifact_bytes"))
    require(10 <= positive_int(limits["max_runtime_seconds"]) <= 86400, "invalid_serverless_runtime")
    require(600 <= positive_int(limits["startup_timeout_seconds"]) <= 3600,
            "serverless_startup_cap_below_baked_worker_bound")
    require(1800 <= positive_int(limits["result_retention_seconds"]) <= 86400,
            "invalid_serverless_result_retention")
    require(positive_int(limits["max_artifact_bytes"]) <= job.MAX_SUBMIT, "serverless_artifact_limit_too_large")
    maximum = money(limits["max_hourly_usd"]) * Decimal(
        limits["max_runtime_seconds"] + limits["startup_timeout_seconds"] + limits["result_retention_seconds"]
        + 10 + policy["idle_timeout_seconds"]) / 3600
    require(money(limits["max_operation_usd"]) >= maximum, "operation_budget_too_small")
    require(money(limits["lifetime_budget_usd"]) >= money(limits["max_operation_usd"]), "lifetime_budget_too_small")
    return policy


def validate_input(value):
    exact_fields(value, ("schema_version", "attempt_id", "job_id", "stage", "manifest_url", "manifest_sha256",
                         "deadline_unix", "runtime_limit_seconds", "claim_get_url", "claim_put_url",
                         "artifact_get_url", "result_manifest_get_url"))
    require(value["schema_version"] == 1 and value["stage"] == "FRI", "serverless_fri_only")
    attempt(value["attempt_id"])
    require(isinstance(value["job_id"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["job_id"]), "invalid_job_id")
    sha256(value["manifest_sha256"])
    positive_int(value["deadline_unix"])
    positive_int(value["runtime_limit_seconds"])
    for name in ("manifest_url", "claim_get_url", "claim_put_url", "artifact_get_url", "result_manifest_get_url"):
        https_url(value[name])
    return value


def validate_operation(value, controller_id, policy):
    exact_fields(value, OP_FIELDS + (("provider_lifetime",) if "provider_lifetime" in value else ()))
    require(value["backend"] == BACKEND and value["controller_id"] == controller_id, "serverless_controller_changed")
    validate_job(value["job"])
    validate_input(value["input"])
    require(value["job"]["job_id"] == value["input"]["job_id"]
            and value["job"]["manifest_sha256"] == value["input"]["manifest_sha256"]
            and value["job"]["manifest_url"] == value["input"]["manifest_url"]
            and value["job"]["result_artifact_url"] == value["input"]["artifact_get_url"]
            and value["job"]["result_manifest_url"] == value["input"]["result_manifest_get_url"]
            and value["deadline"] == value["input"]["deadline_unix"], "serverless_job_binding_changed")
    require(type(value["created_at"]) in (int, float) and 0 <= value["created_at"] < value["deadline"],
            "invalid_serverless_creation_time")
    money(value["reserved_usd"])
    if value["provider_job_id"] is not None:
        identifier(value["provider_job_id"])
    require(value["status"] in ("submit_intent", "submitted", "finished")
            and value["disposition"] in FINAL | {None}, "invalid_serverless_operation_state")
    require(value["status"] != "finished" or value["disposition"] in FINAL, "invalid_serverless_disposition")
    require(value["provider_status"] is None or value["provider_status"] in
            {"IN_QUEUE", "IN_PROGRESS", "ABSENT"} | PROVIDER_FINAL, "invalid_serverless_provider_state")
    require(value["last_error"] is None or isinstance(value["last_error"], str)
            and re.fullmatch(r"[a-z0-9_]{1,128}", value["last_error"]), "invalid_serverless_diagnostic")
    if value["receipt"] is not None:
        exact_fields(value["receipt"], ("sha256", "bytes", "proof_verified"))
        sha256(value["receipt"]["sha256"])
        positive_int(value["receipt"]["bytes"])
        require(value["receipt"]["proof_verified"] is False, "transport_receipt_cannot_verify_proof")
    validate_lifetime(value, policy)
    return value


class ServerlessStore(Store):
    @classmethod
    def initialize(cls, root, policy):
        validate_policy(policy)
        root = Path(root)
        require(root.is_absolute(), "state_directory_must_be_absolute")
        root.mkdir(mode=0o700)
        sync_dir(root.parent)
        store = cls(root)
        store.save({"schema_version": 1, "backend": BACKEND, "controller_id": uuid.uuid4().hex,
                    "policy": policy, "reserved_usd": "0", "operations": {}})
        return store

    def load(self):
        require(not os.path.lexists(self.root / "state.json"), "ambiguous_provider_backend")
        value = read_private_json(self.root / "serverless.json")
        exact_fields(value, ("schema_version", "backend", "controller_id", "policy", "reserved_usd", "operations"))
        require(value["schema_version"] == 1 and value["backend"] == BACKEND, "invalid_serverless_state")
        attempt(value["controller_id"])
        validate_policy(value["policy"])
        require(isinstance(value["operations"], dict) and len(value["operations"]) <= 128,
                "serverless_state_capacity_reached")
        for key, op in value["operations"].items():
            attempt(key)
            validate_operation(op, value["controller_id"], value["policy"])
            require(op["input"]["attempt_id"] == key, "serverless_attempt_changed")
        reserved = money(value["reserved_usd"], allow_zero=True)
        require(reserved <= money(value["policy"]["limits"]["lifetime_budget_usd"])
                and sum(money(op["reserved_usd"]) for op in value["operations"].values()) <= reserved,
                "invalid_serverless_budget_ledger")
        return value

    def save(self, value):
        atomic_json(self.root / "serverless.json", value)


def receipt_controller(store):
    # Pool return recovery reconstructs a generic private Store. A marker selects
    # validation, never authority: both journals or a malformed marker fail closed.
    if isinstance(store, ServerlessStore) or os.path.lexists(store.root / "serverless.json"):
        selected = ServerlessStore(store.root)
        selected.load()
        return ServerlessController(selected, None)
    from runpod import Controller
    return Controller(store, None)


class ServerlessApi:
    def __init__(self, key, http=None):
        require(isinstance(key, str) and key and not any(c.isspace() for c in key), "invalid_api_key")
        self.key, self.http = key, http or Http()

    def endpoint(self, endpoint_id):
        return self.http.json("https://api.runpod.io/v2/serverless/" + identifier(endpoint_id), key=self.key)

    def legacy_endpoint(self, endpoint_id):
        return self.http.json("https://rest.runpod.io/v1/endpoints/" + identifier(endpoint_id) + "?includeTemplate=true",
                              key=self.key)

    def submit(self, endpoint_id, payload):
        return self.http.json("https://api.runpod.ai/v2/" + identifier(endpoint_id) + "/run",
                              method="POST", payload=payload, key=self.key)

    def status(self, endpoint_id, run_id):
        return self.http.json("https://api.runpod.ai/v2/" + identifier(endpoint_id) + "/status/" + identifier(run_id),
                              key=self.key)


class ServerlessController:
    def __init__(self, store, api, clock=time.time, http=None):
        require(isinstance(store, ServerlessStore), "explicit_serverless_store_required")
        self.store, self.api, self.clock, self.http = store, api, clock, http or Http()
        self.state = store.load()
        self.policy, self.limits = self.state["policy"], self.state["policy"]["limits"]

    def save(self):
        self.store.save(self.state)

    def find_operation(self, operation_id):
        attempt(operation_id)
        op = self.state["operations"].get(operation_id)
        if op is None:
            op = self.store.history_json("serverless-op-" + operation_id + ".json")
        if op is not None:
            validate_operation(op, self.state["controller_id"], self.policy)
            require(op["input"]["attempt_id"] == operation_id, "serverless_attempt_changed")
        return op

    def operation(self, operation_id):
        op = self.find_operation(operation_id)
        require(op is not None, "unknown_serverless_operation")
        return op

    def has_job(self, job_id):
        if any(op["job"]["job_id"] == job_id for op in self.state["operations"].values()):
            return True
        key = hashlib.sha256(job_id.encode()).hexdigest()
        index = self.store.history_json("serverless-job-" + key + ".json")
        if index is None:
            return False
        exact_fields(index, ("backend", "controller_id", "job_id", "operation_id"))
        require(index["backend"] == BACKEND and index["controller_id"] == self.state["controller_id"]
                and index["job_id"] == job_id and self.operation(index["operation_id"])["job"]["job_id"] == job_id,
                "serverless_history_changed")
        return True

    def check_capacity(self):
        self.reconcile_completed()
        require(not self.state["operations"],
                "serverless_operation_requires_reconciliation")
        require(len(self.state["operations"]) < 128, "serverless_state_capacity_reached")
        require(money(self.state["reserved_usd"], allow_zero=True) + money(self.limits["max_operation_usd"])
                <= money(self.limits["lifetime_budget_usd"]), "serverless_lifetime_budget_exhausted")

    def lifetime_evidence(self, op, basis, observed_at):
        runtime = int(op["deadline"] - op["created_at"]) if basis == "submit_ack" else self.limits["max_runtime_seconds"]
        return {"basis": basis, "endpoint_id": self.policy["endpoint_id"], "provider_job_id": op["provider_job_id"],
                "anchor_at": timestamp(observed_at), "ttl_ms": (runtime + self.limits["result_retention_seconds"]) * 1000,
                "execution_timeout_ms": runtime * 1000,
                "cleanup_allowance_seconds": self.limits["startup_timeout_seconds"] + 10 + self.policy["idle_timeout_seconds"],
                "closed_at": None, "contradicted_at": None}

    def preflight(self):
        require(self.api is not None, "serverless_api_required")
        endpoint = self.api.endpoint(self.policy["endpoint_id"])
        require(isinstance(endpoint, dict), "invalid_serverless_endpoint")
        expected = {"id": self.policy["endpoint_id"], "image": self.policy["image"], "flashboot": "FLASHBOOT",
                    "workers": {"min": 0, "max": 1, "idleTimeout": self.policy["idle_timeout_seconds"]},
                    "gpu": {"count": 1, "pools": self.policy["gpu_pools"],
                            "allowedCudaVersions": self.policy["allowed_cuda_versions"],
                            "minCudaVersion": self.policy["min_cuda_version"]},
                    "disk": self.policy["disk_gb"]}
        require(all(type(endpoint.get(key)) is type(value) and endpoint.get(key) == value
                    for key, value in expected.items()), "serverless_endpoint_policy_mismatch")
        require(all(type(endpoint["workers"][key]) is int for key in ("min", "max", "idleTimeout"))
                and type(endpoint["gpu"]["count"]) is int, "serverless_endpoint_policy_mismatch")
        require(endpoint.get("type") == "QUEUE" and endpoint.get("scaling") == {"type": "QUEUE_DELAY", "queueDelay": 4},
                "serverless_queue_endpoint_required")
        require(type(endpoint.get("timeout")) is int and 5000 <= endpoint["timeout"]
                <= self.limits["max_runtime_seconds"] * 1000, "serverless_endpoint_timeout_unbounded")
        require(endpoint.get("args") == "" and endpoint.get("entrypoint", []) == []
                and endpoint.get("cmd", []) == [] and endpoint.get("env", {}) == {}
                and endpoint.get("networkVolumes") == [] and endpoint.get("ports", []) == [],
                "serverless_endpoint_container_override")
        legacy = self.api.legacy_endpoint(self.policy["endpoint_id"])
        require(isinstance(legacy, dict) and legacy.get("id") == self.policy["endpoint_id"]
                and legacy.get("templateId") == self.policy["template_id"]
                and legacy.get("gpuTypeIds") == self.policy["gpu_type_ids"]
                and type(legacy.get("gpuCount")) is int and legacy["gpuCount"] == 1
                and legacy.get("computeType") == "GPU", "serverless_hardware_policy_mismatch")
        template = legacy.get("template")
        require(isinstance(template, dict) and template.get("id") == self.policy["template_id"]
                and template.get("imageName") == self.policy["image"]
                and template.get("isServerless") is True, "serverless_template_policy_mismatch")
        # No command override can substitute an unbounded handler for the pinned image.
        require(template.get("dockerStartCmd", []) in ([], "", None), "serverless_template_command_override")
        require(template.get("dockerEntrypoint", []) in ([], "", None)
                and template.get("env", {}) == {}, "serverless_template_command_override")
        return True

    def launch(self, selected, attempt_id, deadline, runtime_seconds, claim_plan):
        attempt(attempt_id)
        validate_job(selected)
        exact_fields(claim_plan, ("claim_get_url", "claim_put_url"))
        for url in claim_plan.values():
            https_url(url)
        require(type(deadline) is int and deadline > 0 and positive_int(runtime_seconds)
                <= self.limits["max_runtime_seconds"], "invalid_serverless_compute_window")
        value = {"schema_version": 1, "attempt_id": attempt_id, "job_id": selected["job_id"], "stage": "FRI",
                 "manifest_url": selected["manifest_url"], "manifest_sha256": selected["manifest_sha256"],
                 "deadline_unix": deadline, "runtime_limit_seconds": runtime_seconds, **claim_plan,
                 "artifact_get_url": selected["result_artifact_url"],
                 "result_manifest_get_url": selected["result_manifest_url"]}
        prior = self.find_operation(attempt_id)
        if prior is not None:
            require(prior["job"] == selected and prior["input"] == value, "serverless_attempt_changed")
            # There is no provider idempotency guarantee. A crash or transport error
            # after intent is reconciled by its durable object result, never POSTed again.
            return attempt_id
        self.check_capacity()
        require(not self.has_job(selected["job_id"]), "serverless_job_already_started")
        now = self.clock()
        remaining = int(deadline - now)
        require(runtime_seconds < remaining <= self.limits["max_runtime_seconds"],
                "serverless_original_deadline_exceeded")
        self.preflight()
        now = self.clock()
        remaining = int(deadline - now)
        require(runtime_seconds < remaining <= self.limits["max_runtime_seconds"],
                "serverless_original_deadline_exceeded")
        reserved = self.limits["max_operation_usd"]
        op = {"backend": BACKEND, "controller_id": self.state["controller_id"], "job": selected,
              "input": value, "created_at": now, "deadline": deadline, "reserved_usd": str(reserved),
              "provider_job_id": None, "provider_status": None, "status": "submit_intent", "receipt": None,
              "disposition": None, "last_error": None}
        self.state["operations"][attempt_id] = op
        self.state["reserved_usd"] = str(money(self.state["reserved_usd"], allow_zero=True) + money(reserved))
        self.save()
        # TTL is a job lifetime bound, NOT result retention: /run results expire
        # 30 minutes after completion regardless of TTL. Late delivery still
        # cannot renew the worker's original absolute computation deadline.
        try:
            response = self.api.submit(self.policy["endpoint_id"], {"input": value,
                "policy": {"executionTimeout": remaining * 1000,
                           "ttl": (remaining + self.limits["result_retention_seconds"]) * 1000}})
            require(isinstance(response, dict) and response.get("status") in ("IN_QUEUE", "IN_PROGRESS"),
                    "invalid_serverless_submit_response")
            op.update(provider_job_id=identifier(response.get("id")), provider_status=response["status"],
                      status="submitted")
            # Receipt of the response is an upper bound on provider acceptance;
            # created_at (before POST) cannot safely anchor a delayed request.
            evidence = self.lifetime_evidence(op, "submit_ack", self.clock())
            validate_lifetime({**op, "provider_lifetime": evidence}, self.policy)
            op["provider_lifetime"] = evidence
        except Exception:
            op["last_error"] = "serverless_submission_uncertain"
            self.save()
            raise Error("serverless_submission_uncertain_preserve_attempt") from None
        self.save()
        return attempt_id

    def tick(self, operation_id):
        op = self.operation(operation_id)
        if op["provider_job_id"] is None or provider_resolved(op):
            return
        require(self.api is not None, "serverless_api_required")
        try:
            response = self.api.status(self.policy["endpoint_id"], op["provider_job_id"])
        except HttpError as error:
            if error.status != 404:
                raise
            op["provider_status"] = "ABSENT"
            observed_at = timestamp(self.clock())
            if "provider_lifetime" not in op:
                op["provider_lifetime"] = self.lifetime_evidence(op, "legacy_observation", observed_at)
            evidence = op["provider_lifetime"]
            require(observed_at >= evidence["anchor_at"], "serverless_lifetime_clock_rollback")
            # A fresh authenticated 404 after the conservative lifetime bound is
            # distinct from proof delivery or an early/missing status. No retry,
            # cancellation, extra compute permission or budget release occurs.
            if observed_at >= lifetime_bound(evidence) and evidence["contradicted_at"] is None:
                evidence["closed_at"] = observed_at
            validate_lifetime(op, self.policy)
        else:
            require(isinstance(response, dict) and response.get("id") == op["provider_job_id"]
                    and response.get("status") in {"IN_QUEUE", "IN_PROGRESS"} | PROVIDER_FINAL,
                    "invalid_serverless_status_response")
            evidence = op.get("provider_lifetime")
            if evidence is not None and response["status"] not in PROVIDER_FINAL:
                observed_at = timestamp(self.clock())
                require(observed_at >= evidence["anchor_at"], "serverless_lifetime_clock_rollback")
                if observed_at >= lifetime_bound(evidence) and evidence["contradicted_at"] is None:
                    # Actual live work after the bound disproves this fallback.
                    # Only a genuine terminal response can then reconcile it.
                    evidence["contradicted_at"] = observed_at
                    op["last_error"] = "serverless_lifetime_contradicted"
            op["provider_status"] = response["status"]
        self.save()

    def collect(self, operation_id):
        op = self.operation(operation_id)
        if op["receipt"] is not None:
            self.verify_receipt(operation_id)
            return True
        try:
            manifest = self.http.json(op["job"]["result_manifest_url"], limit=64 * 1024)
        except HttpError as error:
            if error.status == 404:
                return False
            raise
        exact_fields(manifest, ("schema_version", "operation_id", "job_id", "manifest_sha256",
                                "artifact_sha256", "artifact_bytes"))
        require(manifest["schema_version"] == 1 and manifest["operation_id"] == operation_id
                and manifest["job_id"] == op["job"]["job_id"]
                and manifest["manifest_sha256"] == op["job"]["manifest_sha256"], "result_job_mismatch")
        expected, size = sha256(manifest["artifact_sha256"]), positive_int(manifest["artifact_bytes"])
        require(size <= self.limits["max_artifact_bytes"], "artifact_too_large")
        destination = self.store.root / (operation_id + ".proof")
        temporary = self.store.root / ("." + operation_id + ".partial")
        if not os.path.lexists(destination):
            temporary.unlink(missing_ok=True)
            try:
                with os.fdopen(private_open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb") as output:
                    self.http.transfer(op["job"]["result_artifact_url"], output, size)
                    output.flush()
                    os.fsync(output.fileno())
                check_artifact(temporary, expected, size)
                os.replace(temporary, destination)
                sync_dir(destination.parent)
            finally:
                temporary.unlink(missing_ok=True)
        check_artifact(destination, expected, size)
        op["receipt"] = {"sha256": expected, "bytes": size, "proof_verified": False}
        self.save()
        return True

    def verify_receipt(self, operation_id):
        receipt = self.operation(operation_id)["receipt"]
        require(receipt is not None, "durable_artifact_required")
        check_artifact(self.store.root / (operation_id + ".proof"), receipt["sha256"], receipt["bytes"])

    def finish(self, operation_id, disposition):
        require(disposition in FINAL, "invalid_serverless_disposition")
        op = self.operation(operation_id)
        require(op["disposition"] in (None, disposition), "serverless_disposition_changed")
        if disposition == "expired":
            require(self.clock() >= op["deadline"] and op["receipt"] is None
                    and provider_resolved(op), "serverless_provider_deadline_not_elapsed")
        else:
            self.verify_receipt(operation_id)
        op.update(status="finished", disposition=disposition)
        self.save()
        # An uploaded proof is independent of Runpod's execution disposition. Keep
        # unknown submissions blocking new spend until their run is identified.
        if not provider_resolved(op):
            return
        self.archive(operation_id)

    def archive(self, operation_id):
        op = self.operation(operation_id)
        require(op["disposition"] in FINAL and provider_resolved(op),
                "serverless_operation_requires_reconciliation")
        if op["disposition"] != "expired":
            self.verify_receipt(operation_id)
        self.store.retain_history("serverless-op-" + operation_id + ".json", op)
        self.store.retain_history("serverless-job-" + hashlib.sha256(op["job"]["job_id"].encode()).hexdigest() + ".json",
            {"backend": BACKEND, "controller_id": self.state["controller_id"], "job_id": op["job"]["job_id"],
             "operation_id": operation_id})
        self.state["operations"].pop(operation_id, None)
        self.save()

    def reconcile_completed(self):
        for operation_id, op in list(self.state["operations"].items()):
            if op["disposition"] in FINAL:
                self.tick(operation_id)
                if provider_resolved(op):
                    self.archive(operation_id)

    def bind_completed_run(self, operation_id, run_id):
        op = self.operation(operation_id)
        require(op.get("provider_lifetime", {}).get("closed_at") is None,
                "serverless_lifetime_already_closed")
        require(op["provider_job_id"] in (None, run_id), "serverless_run_changed")
        response = self.api.status(self.policy["endpoint_id"], identifier(run_id))
        require(isinstance(response, dict) and response.get("id") == run_id
                and response.get("status") == "COMPLETED", "serverless_completed_run_required")
        output = response.get("output")
        exact_fields(output, ("schema_version", "operation_id", "job_id", "manifest_sha256",
                              "artifact_sha256", "artifact_bytes"))
        require(output["schema_version"] == 1 and output["operation_id"] == operation_id
                and output["job_id"] == op["job"]["job_id"]
                and output["manifest_sha256"] == op["job"]["manifest_sha256"], "result_job_mismatch")
        require(self.collect(operation_id) and output["artifact_sha256"] == op["receipt"]["sha256"]
                and output["artifact_bytes"] == op["receipt"]["bytes"], "serverless_result_not_durable")
        op.update(provider_job_id=run_id, provider_status="COMPLETED", status="submitted"
                  if op["disposition"] is None else "finished", last_error=None)
        self.save()
        if op["disposition"] in FINAL:
            self.archive(operation_id)

    def status(self):
        return {"backend": BACKEND, "endpoint_id": self.policy["endpoint_id"],
                "reserved_usd": self.state["reserved_usd"], "operations": [
                    {"attempt_id": key, **{field: value[field] for field in
                      ("status", "deadline", "provider_job_id", "provider_status", "disposition", "last_error")},
                     "provider_lifetime": value.get("provider_lifetime")}
                    for key, value in self.state["operations"].items()]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--state-dir", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--policy", required=True, type=Path)
    commands.add_parser("status")
    commands.add_parser("validate-endpoint")
    reconcile = commands.add_parser("bind-completed-run")
    reconcile.add_argument("--operation", required=True)
    reconcile.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            policy = validate_policy(read_private_json(args.policy))
            if args.execute:
                ServerlessStore.initialize(args.state_dir, policy)
            print(job.encode({"action": "initialized" if args.execute else "plan_init", "backend": BACKEND,
                              "endpoint_id": policy["endpoint_id"], "flashboot": True}).decode())
            return 0
        store = ServerlessStore(args.state_dir)
        with store.lock():
            controller = ServerlessController(store, None)
            if args.command in ("validate-endpoint", "bind-completed-run"):
                require(args.execute, "endpoint_validation_requires_execute_for_read_only_api")
                controller.api = ServerlessApi(os.environ.get("RUNPOD_API_KEY", ""))
                if args.command == "validate-endpoint":
                    controller.preflight()
                else:
                    controller.bind_completed_run(args.operation, args.run_id)
            print(job.encode({"action": args.command, **controller.status()}).decode())
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError):
        print('{"error":"serverless_configuration_or_state_failure"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
