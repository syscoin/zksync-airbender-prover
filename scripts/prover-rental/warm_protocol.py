"""Authenticated, sequential commands for one bounded rental session."""

import hashlib
import hmac
import json
import re

from runpod import exact_fields, https_url, positive_int, require, sha256


MAX_MESSAGE_BYTES = 64 * 1024
MAX_JOBS = 1000
COMMAND_DOMAIN = b"zksys-warm-command-v1\0"
FINISHED_DOMAIN = b"zksys-warm-finished-v1\0"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value), "invalid_warm_identity")
    return value


def key_bytes(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_session_key")
    return bytes.fromhex(value)


def validate_session(value):
    exact_fields(value, ("schema_version", "session_id", "mailbox_url", "finished_manifest_url",
                         "finished_manifest_put_url", "session_key", "poll_interval_seconds"))
    require(value["schema_version"] == 1, "unsupported_warm_schema")
    identity(value["session_id"])
    key_bytes(value["session_key"])
    for name in ("mailbox_url", "finished_manifest_url", "finished_manifest_put_url"):
        https_url(value[name])
    require(positive_int(value["poll_interval_seconds"]) <= 60, "invalid_warm_poll_interval")
    return value


def validate_command(body):
    common = ("session_id", "operation_id", "sequence", "kind", "expires_at", "previous_command_sha256")
    require(isinstance(body, dict) and body.get("kind") in ("job", "stop"), "invalid_warm_command")
    extra = (("attempt_id", "stage", "job_id", "manifest_url", "manifest_sha256", "runtime_limit_seconds")
             if body["kind"] == "job" else ())
    exact_fields(body, (*common, *extra))
    identity(body["session_id"])
    identity(body["operation_id"])
    require(positive_int(body["sequence"]) <= MAX_JOBS + 1, "warm_sequence_limit")
    positive_int(body["expires_at"])
    if body["sequence"] == 1:
        require(body["previous_command_sha256"] is None, "unexpected_previous_warm_command")
    else:
        sha256(body["previous_command_sha256"])
    if body["kind"] == "job":
        require(body["sequence"] <= MAX_JOBS, "warm_job_limit")
        identity(body["attempt_id"])
        require(body["stage"] in ("FRI", "SNARK"), "invalid_warm_stage")
        require(isinstance(body["job_id"], str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", body["job_id"]),
                "invalid_job_id")
        https_url(body["manifest_url"])
        sha256(body["manifest_sha256"])
        positive_int(body["runtime_limit_seconds"])
    return body


def _sign(body, key, domain):
    raw = encode(body)
    require(len(raw) <= MAX_MESSAGE_BYTES // 2, "warm_message_too_large")
    return {"schema_version": 1, "body": body,
            "mac": hmac.new(key_bytes(key), domain + raw, hashlib.sha256).hexdigest()}


def _verify(envelope, key, domain):
    exact_fields(envelope, ("schema_version", "body", "mac"))
    require(envelope["schema_version"] == 1, "unsupported_warm_schema")
    sha256(envelope["mac"])
    expected = _sign(envelope["body"], key, domain)
    require(hmac.compare_digest(expected["mac"], envelope["mac"]), "warm_authentication_failed")
    return envelope["body"]


def sign_command(body, key):
    validate_command(body)
    return _sign(body, key, COMMAND_DOMAIN)


def verify_command(envelope, key):
    return validate_command(_verify(envelope, key, COMMAND_DOMAIN))


def command_hash(envelope):
    return hashlib.sha256(encode(envelope)).hexdigest()


def validate_finished(body):
    exact_fields(body, ("session_id", "operation_id", "sequence", "command_sha256", "completed_jobs", "status"))
    identity(body["session_id"])
    identity(body["operation_id"])
    sha256(body["command_sha256"])
    require(body["status"] == "finished", "warm_session_not_finished")
    require(type(body["completed_jobs"]) is int and 0 <= body["completed_jobs"] <= MAX_JOBS,
            "invalid_completed_job_count")
    require(positive_int(body["sequence"]) == body["completed_jobs"] + 1, "invalid_finished_sequence")
    return body


def sign_finished(body, key):
    validate_finished(body)
    return _sign(body, key, FINISHED_DOMAIN)


def verify_finished(envelope, key):
    return validate_finished(_verify(envelope, key, FINISHED_DOMAIN))
