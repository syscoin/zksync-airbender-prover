import io
import unittest

import runpod
import storage


def config():
    return {"endpoint_url": "https://s3.example.test", "region": "test-1", "bucket": "private-proofs",
            "prefix": "warm/proofs", "profile": None, "url_ttl_seconds": 7200}


class ClientError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class S3:
    def __init__(self):
        self.objects, self.puts, self.signatures = {}, [], []
        self.failure = None

    def generate_presigned_url(self, method, Params, ExpiresIn):
        self.signatures.append((method, Params, ExpiresIn))
        return "https://s3.example.test/" + Params["Key"] + "?method=" + method

    def put_object(self, **params):
        self.puts.append(params)
        if self.failure:
            raise ClientError(self.failure)
        key = params["Key"]
        if params.get("IfNoneMatch") == "*" and key in self.objects:
            raise ClientError("PreconditionFailed")
        self.objects[key] = params["Body"]

    def get_object(self, Bucket, Key):
        return {"ContentLength": len(self.objects[Key]), "Body": io.BytesIO(self.objects[Key])}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.client = S3()
        self.storage = storage.S3Storage(config(), self.client, clock=lambda: 1000)
        self.identifier = "a" * 32

    def test_scoped_plans_have_only_object_urls_and_bounded_expiry(self):
        session = self.storage.session_plan(self.identifier)
        plan = self.storage.job_plan(self.identifier)
        self.assertEqual(session["expires_at"], 8200)
        self.assertEqual(len(plan), 8)
        self.assertEqual(len(self.client.signatures), 11)
        for method, params, ttl in self.client.signatures:
            self.assertEqual(set(params), {"Bucket", "Key"})
            self.assertIn("/" + self.identifier + "/", params["Key"])
            self.assertEqual(ttl, 7200)
            self.assertIn(method, ("get_object", "put_object"))

    def test_immutable_retry_checks_exact_content_and_never_overwrites(self):
        self.storage.write_object("key", b'{"value":1}')
        self.storage.write_object("key", b'{"value":1}')
        with self.assertRaisesRegex(runpod.Error, "immutable_object_changed"):
            self.storage.write_object("key", b'{"value":2}')
        self.assertEqual(self.client.objects["key"], b'{"value":1}')
        self.assertTrue(all(put["IfNoneMatch"] == "*" for put in self.client.puts))

    def test_mutable_mailbox_is_no_store_and_upload_adapter_rejects_unrelated_urls(self):
        self.storage.publish_command(self.identifier, b'{"sequence":1}')
        self.storage.publish_command(self.identifier, b'{"sequence":2}')
        self.assertNotIn("IfNoneMatch", self.client.puts[-1])
        self.assertEqual(self.client.puts[-1]["CacheControl"], "no-store")
        plan = self.storage.job_plan(self.identifier)
        upload = self.storage.job_transport(self.identifier, plan)
        upload.put(plan["payload_put_url"], b"{}")
        with self.assertRaisesRegex(runpod.Error, "unexpected_trusted_upload_url"):
            upload.put(plan["artifact_put_url"], b"{}")

    def test_ambiguous_put_fails_without_mutating_or_replacing_object(self):
        self.client.failure = "RequestTimeout"
        with self.assertRaisesRegex(runpod.Error, "storage_write_failed"):
            self.storage.write_object("key", b"{}")
        self.assertEqual(self.client.objects, {})

    def test_size_checks_and_invalid_scope_fail_closed(self):
        self.client.objects["key"] = b"large"
        with self.assertRaisesRegex(runpod.Error, "too_large"):
            self.storage.read_object("key", 2)
        for change in ({"url_ttl_seconds": 604801}, {"endpoint_url": "http://unsafe.test"},
                       {"prefix": "../escape"}, {"profile": "../escape"}):
            with self.subTest(change=change), self.assertRaises(runpod.Error):
                storage.validate_config({**config(), **change})
        with self.assertRaises(runpod.Error):
            self.storage.job_plan("../escape")


if __name__ == "__main__":
    unittest.main()
