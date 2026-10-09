import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("rental_serverless_runner", Path(__file__).with_name("serverless_runner.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ServerlessRunnerTests(unittest.TestCase):
    def run_worker(self, *, initialize_error=None, start_error=None):
        events = []

        class Worker:
            def initialize(self):
                events.append("initialize")
                if initialize_error:
                    raise initialize_error

            async def handler(self, _request):
                return {}

            def close(self):
                events.append("close")

        worker = Worker()

        def start(config):
            events.append("start")
            self.assertEqual(config["handler"], worker.handler)
            self.assertFalse(config["refresh_worker"])
            for current in (0, 1, 8):
                self.assertEqual(config["concurrency_modifier"](current), 1)
            if start_error:
                raise start_error

        sdk = SimpleNamespace(serverless=SimpleNamespace(start=start))

        def load(name):
            events.append(name)
            return sdk if name == "runpod" else SimpleNamespace(ServerlessFriWorker=lambda: worker)

        with patch.object(runner.importlib, "import_module", side_effect=load), \
                patch.object(runner, "version", return_value="1.12.0"), patch.object(sys, "path", sys.path.copy()):
            if initialize_error or start_error:
                with self.assertRaises(RuntimeError):
                    runner.main()
            else:
                runner.main()
        return events

    def test_sdk_loads_first_and_native_initialization_precedes_job_polling(self):
        self.assertEqual(self.run_worker(), ["runpod", "serverless_worker", "initialize", "start", "close"])

    def test_native_runtime_closes_after_initialization_or_sdk_failure(self):
        self.assertEqual(self.run_worker(initialize_error=RuntimeError("cold_start_failed")),
                         ["runpod", "serverless_worker", "initialize", "close"])
        self.assertEqual(self.run_worker(start_error=RuntimeError("provider_failed")),
                         ["runpod", "serverless_worker", "initialize", "start", "close"])

    def test_unexpected_sdk_version_never_initializes_native_worker(self):
        with patch.object(runner.importlib, "import_module") as load, \
                patch.object(runner, "version", return_value="1.13.0"):
            with self.assertRaisesRegex(RuntimeError, "serverless_sdk_version_mismatch"):
                runner.main()
        load.assert_called_once_with("runpod")


if __name__ == "__main__":
    unittest.main()
