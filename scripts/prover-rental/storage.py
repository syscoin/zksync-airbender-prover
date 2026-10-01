"""Trusted-host S3 object plans. Storage credentials never enter worker commands."""

import re
import time

import job
from runpod import Error, exact_fields, https_url, positive_int, require


def validate_config(config):
    exact_fields(config, ("endpoint_url", "region", "bucket", "prefix", "profile", "url_ttl_seconds"))
    https_url(config["endpoint_url"])
    require("?" not in config["endpoint_url"], "storage_endpoint_must_not_have_query")
    require(isinstance(config["region"], str) and re.fullmatch(r"[A-Za-z0-9-]{1,64}", config["region"]),
            "invalid_storage_region")
    require(isinstance(config["bucket"], str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", config["bucket"]),
            "invalid_storage_bucket")
    require(isinstance(config["prefix"], str) and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", config["prefix"])
            and len(config["prefix"]) <= 256, "invalid_storage_prefix")
    require(config["profile"] is None or isinstance(config["profile"], str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", config["profile"]), "invalid_storage_profile")
    require(60 <= positive_int(config["url_ttl_seconds"]) <= 604800, "invalid_storage_url_ttl")
    return config


def object_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value), "invalid_storage_object_id")
    return value


def error_code(error):
    response = getattr(error, "response", {})
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


class S3Storage:
    def __init__(self, config, client=None, clock=time.time):
        self.config, self.clock = validate_config(config), clock
        if client is None:
            # Importing the supervisor and its dry run must not load credentials or
            # require provider SDKs. Boto's standard credential chain stays here.
            try:
                import boto3
                from botocore.config import Config
            except ImportError:
                raise Error("install_requirements_controller_for_execute") from None
            try:
                session = boto3.Session(profile_name=config["profile"])
                client = session.client("s3", endpoint_url=config["endpoint_url"], region_name=config["region"],
                    config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=30,
                                  retries={"max_attempts": 2, "mode": "standard"}))
            except Exception:
                raise Error("storage_client_initialization_failed") from None
        self.client = client

    def key(self, kind, identifier, filename):
        require(kind in ("jobs", "sessions"), "invalid_storage_namespace")
        object_id(identifier)
        require(re.fullmatch(r"[a-z-]+\.json", filename), "invalid_storage_filename")
        return f"{self.config['prefix']}/{kind}/{identifier}/{filename}"

    def signed_url(self, key, method):
        require(method in ("get_object", "put_object"), "invalid_storage_method")
        try:
            url = self.client.generate_presigned_url(method,
                Params={"Bucket": self.config["bucket"], "Key": key},
                ExpiresIn=self.config["url_ttl_seconds"])
            return https_url(url)
        except Exception:
            raise Error("storage_presign_failed") from None

    def session_plan(self, identifier):
        mailbox = self.key("sessions", identifier, "command.json")
        finished = self.key("sessions", identifier, "finished.json")
        return {"mailbox_key": mailbox, "mailbox_url": self.signed_url(mailbox, "get_object"),
                "finished_manifest_url": self.signed_url(finished, "get_object"),
                "finished_manifest_put_url": self.signed_url(finished, "put_object"),
                "expires_at": int(self.clock()) + self.config["url_ttl_seconds"]}

    def job_plan(self, identifier):
        plan = {}
        for part in ("payload", "manifest", "artifact", "result_manifest"):
            key = self.key("jobs", identifier, part.replace("_", "-") + ".json")
            for action in ("get", "put"):
                plan[f"{part}_{action}_url"] = self.signed_url(key, action + "_object")
        return plan

    def read_object(self, key, maximum):
        try:
            response = self.client.get_object(Bucket=self.config["bucket"], Key=key)
            body = response["Body"]
            try:
                require(type(response.get("ContentLength")) is int and 0 <= response["ContentLength"] <= maximum,
                        "storage_object_too_large")
                raw = body.read(maximum + 1)
            finally:
                body.close()
            require(len(raw) == response["ContentLength"] and len(raw) <= maximum, "storage_object_size_mismatch")
            return raw
        except Error:
            raise
        except Exception:
            raise Error("storage_read_failed") from None

    def write_object(self, key, raw, immutable=True):
        require(isinstance(raw, bytes) and len(raw) <= max(job.MAX_PICK.values()), "storage_object_too_large")
        params = {"Bucket": self.config["bucket"], "Key": key, "Body": raw,
                  "ContentType": "application/json", "CacheControl": "no-store"}
        if immutable:
            params["IfNoneMatch"] = "*"
        try:
            self.client.put_object(**params)
        except Exception as error:
            if immutable and error_code(error) in ("PreconditionFailed", "412"):
                require(self.read_object(key, len(raw)) == raw, "storage_immutable_object_changed")
                return
            raise Error("storage_write_failed") from None

    def publish_command(self, identifier, raw):
        require(len(raw) <= job.MAX_MANIFEST, "mailbox_command_too_large")
        self.write_object(self.key("sessions", identifier, "command.json"), raw, immutable=False)

    def job_transport(self, identifier, plan):
        return JobUpload(self, identifier, plan)


class JobUpload:
    def __init__(self, storage, identifier, plan):
        import sentry
        sentry.validate_storage_plan(plan)
        self.storage = storage
        self.urls = {plan[f"{part}_put_url"]: storage.key("jobs", identifier, part + ".json")
                     for part in ("payload", "manifest")}

    def put(self, url, raw, deadline=None):
        require(url in self.urls, "unexpected_trusted_upload_url")
        self.storage.write_object(self.urls[url], raw)
