from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runpod
from test_runpod import FakeApi, policy
from test_warm import session


class HistoryDurabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = runpod.Store.initialize(Path(temporary.name) / "controller", policy())
        self.api = FakeApi()
        self.store.heartbeat(1000)
        watchdog = self.store.lock("watchdog.lock")
        watchdog.__enter__()
        self.addCleanup(watchdog.__exit__, None, None, None)
        self.operation_id = self.controller().launch_session(session())
        self.history = self.store.root / "history"
        self.archive = self.history / ("operation-" + self.operation_id + ".json")

    def controller(self):
        return runpod.Controller(self.store, self.api, clock=lambda: 1000)

    def assert_barriers_before_summary(self, recovery):
        events = []
        sync, save = runpod.sync_dir, self.store.save
        def synced(path):
            sync(path)
            events.append(Path(path))
        def saved(state):
            self.assertIn("archive_sha256", state["operations"][self.operation_id])
            self.assertNotIn("archive_sha256", self.store.load()["operations"][self.operation_id])
            self.assertIn(self.history, events)
            self.assertIn(self.store.root, events)
            save(state)
        with patch.object(runpod, "sync_dir", side_effect=synced), patch.object(self.store, "save", side_effect=saved):
            recovery(self.controller())
        self.assertIn("archive_sha256", self.store.load()["operations"][self.operation_id])
        self.assertEqual(self.controller().operation(self.operation_id)["status"], "terminated")
        self.assertEqual([call[0] for call in self.api.calls].count("create"), 1)
        self.assertEqual([call[0] for call in self.api.calls].count("delete"), 1)

    def test_existing_archive_is_synced_before_replacing_stale_inline_authority(self):
        sync = runpod.sync_dir
        def interrupted(path):
            if Path(path) == self.history:
                self.assertTrue(self.archive.exists())
                raise KeyboardInterrupt()
            sync(path)
        with patch.object(runpod, "sync_dir", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.controller().terminate(self.operation_id, failure=True)
        self.assertTrue(self.archive.exists())
        self.assertEqual(self.store.load()["operations"][self.operation_id]["status"], "delete_uncertain")
        self.assert_barriers_before_summary(lambda controller: controller.save())

    def test_existing_history_directory_is_synced_to_parent_before_inline_removal(self):
        sync = runpod.sync_dir
        def interrupted(path):
            if Path(path) == self.store.root and self.history.exists():
                self.assertFalse(self.archive.exists())
                raise KeyboardInterrupt()
            sync(path)
        with patch.object(runpod, "sync_dir", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.controller().terminate(self.operation_id, failure=True)
        self.assertTrue(self.history.exists())
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.store.load()["operations"][self.operation_id]["status"], "delete_uncertain")
        self.assert_barriers_before_summary(lambda controller: controller.reconcile(self.operation_id))


if __name__ == "__main__":
    unittest.main()
