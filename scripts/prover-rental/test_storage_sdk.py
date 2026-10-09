"""Offline contract checks against the optional trusted-host SDK."""

import unittest
from urllib.parse import parse_qs, urlsplit

import storage

try:
    import boto3
    from botocore.config import Config
    from botocore.stub import Stubber
except ImportError:
    boto3 = None


@unittest.skipIf(boto3 is None, "install requirements-controller.txt for offline SDK checks")
class StorageSdkTests(unittest.TestCase):
    def test_presigned_worker_requests_need_no_undisclosed_headers(self):
        client = boto3.client("s3", endpoint_url="https://storage.example", region_name="us-east-1",
            aws_access_key_id="TEST_ONLY_ACCESS_KEY", aws_secret_access_key="TEST_ONLY_SECRET",
            config=Config(signature_version="s3v4"))
        config = {"endpoint_url": "https://storage.example", "region": "us-east-1",
                  "bucket": "test-prover-bucket", "prefix": "test-prover", "profile": None,
                  "url_ttl_seconds": 3600}
        objects = storage.S3Storage(config, client=client, clock=lambda: 1000)
        for name, url in objects.job_plan("1" * 32).items():
            with self.subTest(capability=name):
                query = parse_qs(urlsplit(url).query)
                self.assertEqual(query["X-Amz-Algorithm"], ["AWS4-HMAC-SHA256"])
                self.assertEqual(query["X-Amz-SignedHeaders"], ["host"])
                self.assertFalse(any("checksum" in key.lower() for key in query))
        claim = objects.compute_claim_plan("1" * 32)
        self.assertEqual(parse_qs(urlsplit(claim["claim_get_url"]).query)["X-Amz-SignedHeaders"], ["host"])
        signed = parse_qs(urlsplit(claim["claim_put_url"]).query)
        self.assertEqual(signed["X-Amz-SignedHeaders"], ["host;if-none-match"])
        self.assertFalse(any("checksum" in key.lower() for key in signed))
        with Stubber(client) as stub:
            stub.add_response("put_object", {}, {"Bucket": config["bucket"],
                "Key": "test-prover/jobs/test.json", "Body": b"{}", "ContentType": "application/json",
                "CacheControl": "no-store", "IfNoneMatch": "*"})
            objects.write_object("test-prover/jobs/test.json", b"{}")
            stub.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
