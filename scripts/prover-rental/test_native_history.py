import copy
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import job
import runpod
import sentry
import test_supervisor


class NativeHistoryTests(unittest.TestCase):
    def completed(self, finish=True):
        harness = test_supervisor.SupervisorTests(methodName="runTest")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        harness.native.ready.add(("child", "FRI"))
        harness.instance.tick()
        active = copy.deepcopy(harness.instance.state["active"])
        self.assertEqual(harness.pod().tick(), "completed")
        operation_id = active["rental_operation"]
        directory = harness.instance.directory(active)
        with harness.provider.lock():
            self.assertTrue(harness.instance.controller().collect(operation_id))
        source = harness.instance.source(active["source"])
        self.assertEqual(sentry.submit(directory, harness.provider, operation_id,
                         harness.instance.auth(source), harness.native), "accepted")
        if finish:
            with harness.provider.lock():
                harness.instance.controller().finish_warm_job(operation_id, "accepted")
        expected = {"job_id": active["job_id"], "stage": active["stage"], "endpoint": source["endpoint"],
                    "release_sha256": harness.instance.settings["releases"][active["stage"]],
                    "chain_binding": active["chain_binding"]}
        return harness, directory, operation_id, expected

    def setUp(self):
        self.harness, self.directory, self.operation_id, self.expected = self.completed()
        self.marker = self.directory / sentry.NATIVE_COMPLETION

    def compact(self, execute=True):
        return sentry.compact_native(self.directory, self.harness.provider, self.operation_id, self.expected, execute)

    def files(self):
        return {path.name: path.read_bytes() for path in self.directory.iterdir() if path.is_file()}

    def test_preview_is_readonly_and_archive_repeats_without_bulk_originals(self):
        before = self.files()
        provider = {str(path): path.read_bytes() for path in self.harness.provider.root.rglob("*") if path.is_file()}
        with patch.object(self.harness.provider, "lock", side_effect=AssertionError("preview must not lock")), \
                patch.object(sentry, "sync_dir", side_effect=AssertionError("preview must not fsync")), \
                patch.object(runpod, "sync_dir", side_effect=AssertionError("preview must not fsync")):
            preview = self.compact(False)
        self.assertEqual(self.files(), before)
        self.assertEqual(provider, {str(path): path.read_bytes() for path in self.harness.provider.root.rglob("*") if path.is_file()})
        self.assertEqual(self.compact(), preview)
        self.assertEqual(self.compact(False), preview)
        self.assertEqual(self.compact(), preview)
        self.assertEqual(set(self.files()), {*sentry.NATIVE_RETAINED, sentry.NATIVE_COMPLETION})
        for name in sentry.NATIVE_BULK:
            self.assertEqual(preview["files"][name], {"sha256": job.hash_bytes(before[name]), "bytes": len(before[name])})
        for name in sentry.NATIVE_RETAINED:
            self.assertEqual((self.directory / name).read_bytes(), before[name])
        self.assertEqual(provider, {str(path): path.read_bytes() for path in self.harness.provider.root.rglob("*") if path.is_file()})

    def test_missing_original_without_archive_is_not_treated_as_completed_cleanup(self):
        (self.directory / "payload.json").unlink()
        before = self.files()
        with self.assertRaises(FileNotFoundError):
            self.compact()
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.files(), before)

    def test_private_single_link_files_are_required_before_any_pruning(self):
        for name, kind in (("payload.json", "public"), ("submission.json", "symlink"),
                           ("evidence.json", "hardlink"), ("authority.json", "hardlink")):
            with self.subTest(name=name, kind=kind):
                harness, directory, operation_id, expected = self.completed()
                target = directory / name
                if kind == "public":
                    target.chmod(0o644)
                elif kind == "symlink":
                    target.rename(directory / "untouched-target")
                    target.symlink_to(directory / "untouched-target")
                else:
                    os.link(target, directory / "untouched-link")
                before = {path.name: path.read_bytes() for path in directory.iterdir()}
                with self.assertRaises((runpod.Error, OSError)):
                    sentry.compact_native(directory, harness.provider, operation_id, expected)
                self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})
                self.assertFalse((directory / sentry.NATIVE_COMPLETION).exists())

    def test_named_pipe_is_rejected_without_blocking_or_pruning(self):
        target = self.directory / "submission.json"
        target.unlink()
        os.mkfifo(target, 0o600)
        before = {path.name: path.read_bytes() for path in self.directory.iterdir() if path != target}
        with self.assertRaisesRegex(runpod.Error, "unsafe_native_completion_file"):
            self.compact(False)
        with self.assertRaisesRegex(runpod.Error, "unsafe_native_completion_file"):
            self.compact()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir() if path != target})
        self.assertFalse(self.marker.exists())

    def test_provider_archive_named_pipe_is_rejected_before_controller_lookup(self):
        archive = self.harness.provider.root / "history" / ("operation-" + self.operation_id + ".json")
        archive.unlink()
        os.mkfifo(archive, 0o600)
        before = self.files()
        state = (self.harness.provider.root / "state.json").read_bytes()
        with patch.object(sentry.Controller, "operation", side_effect=AssertionError("unsafe archive lookup")):
            for execute in (False, True):
                with self.subTest(execute=execute), self.assertRaisesRegex(runpod.Error, "unsafe_native_completion_file"):
                    self.compact(execute)
        self.assertEqual(before, self.files())
        self.assertEqual((self.harness.provider.root / "state.json").read_bytes(), state)
        self.assertFalse(self.marker.exists())

    def test_changed_bulk_or_expected_identity_prevents_all_pruning(self):
        for name in ("payload.json", "evidence.json", "submission.json"):
            target = self.directory / name
            original = target.read_bytes()
            target.write_bytes(original + b" ")
            before = self.files()
            with self.assertRaisesRegex(runpod.Error, "bulk_binding_changed"):
                self.compact()
            self.assertEqual(before, self.files())
            target.write_bytes(original)
        self.expected["job_id"] = "foreign:job"
        before = self.files()
        with self.assertRaisesRegex(runpod.Error, "authority_changed"):
            self.compact()
        self.assertEqual(before, self.files())

    def test_unfinished_provider_or_uncertain_native_disposition_cannot_prune(self):
        harness, directory, operation_id, expected = self.completed(False)
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        with self.assertRaisesRegex(runpod.Error, "provider_changed"):
            sentry.compact_native(directory, harness.provider, operation_id, expected)
        self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})
        authority = runpod.read_private_json(self.directory / "authority.json")
        authority["status"] = "submission_pending"
        runpod.atomic_json(self.directory / "authority.json", authority)
        before = self.files()
        with self.assertRaisesRegex(runpod.Error, "authority_changed"):
            self.compact()
        self.assertEqual(before, self.files())

    def test_marker_rename_crash_restores_archive_and_directory_barriers_before_unlink(self):
        sync = runpod.sync_dir
        def interrupted(path):
            if Path(path) == self.directory and self.marker.exists():
                raise KeyboardInterrupt()
            sync(path)
        with patch.object(runpod, "sync_dir", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.compact()
        self.assertTrue(self.marker.is_file())
        self.assertTrue(all((self.directory / name).is_file() for name in sentry.NATIVE_BULK))
        observed, deleted = [], []
        def synced(path):
            sync(path)
            observed.append(Path(path))
        unlink = Path.unlink
        def checked_unlink(path, *args, **kwargs):
            if path.parent == self.directory and path.name in sentry.NATIVE_BULK:
                for required in (self.harness.provider.root / "history", self.harness.provider.root,
                                 self.directory, self.directory.parent):
                    self.assertIn(required, observed)
                deleted.append(path.name)
            return unlink(path, *args, **kwargs)
        with patch.object(runpod, "sync_dir", side_effect=synced), patch.object(sentry, "sync_dir", side_effect=synced), \
                patch.object(Path, "unlink", new=checked_unlink):
            self.compact()
        self.assertEqual(deleted, list(sentry.NATIVE_BULK))
        self.assertEqual(observed[-1], self.directory)

    def test_existing_provider_archive_fsync_failure_precedes_marker_and_deletion(self):
        before = self.files()
        sync = runpod.sync_dir
        def interrupted(path):
            if Path(path) == self.harness.provider.root / "history":
                raise KeyboardInterrupt()
            sync(path)
        with patch.object(runpod, "sync_dir", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.compact()
        self.assertEqual(before, self.files())

    def test_partial_deletion_revalidates_every_remaining_file_before_resuming(self):
        unlink = Path.unlink
        def interrupted(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path == self.directory / "payload.json":
                raise KeyboardInterrupt()
            return result
        with patch.object(Path, "unlink", new=interrupted), self.assertRaises(KeyboardInterrupt):
            self.compact()
        self.assertTrue(self.marker.is_file())
        target = self.directory / "submission.json"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        before = self.files()
        with self.assertRaisesRegex(runpod.Error, "bulk_changed"):
            self.compact()
        self.assertEqual(self.files(), before)
        target.write_bytes(original)
        self.compact()
        self.assertTrue(all(not (self.directory / name).exists() for name in sentry.NATIVE_BULK))

    def test_all_deleted_restart_reestablishes_final_directory_fsync(self):
        sync = sentry.sync_dir
        def interrupted(path):
            if Path(path) == self.directory and all(not (self.directory / name).exists() for name in sentry.NATIVE_BULK):
                raise KeyboardInterrupt()
            sync(path)
        with patch.object(sentry, "sync_dir", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.compact()
        before = self.files()
        observed = []
        def synced(path):
            sync(path)
            observed.append(Path(path))
        with patch.object(sentry, "sync_dir", side_effect=synced):
            self.compact()
        self.assertEqual(self.files(), before)
        self.assertEqual(observed, [self.directory, self.directory.parent, self.directory])

    def test_retained_metadata_and_provider_proof_remain_required_after_cleanup(self):
        self.compact()
        for path in (self.directory / "controller-job.json", self.harness.provider.root / (self.operation_id + ".proof")):
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.assertRaises(runpod.Error):
                self.compact()
            path.write_bytes(original)
        self.compact()

    def legacy_inline(self):
        controller = self.harness.instance.controller()
        operation = copy.deepcopy(controller.operation(self.operation_id))
        state = self.harness.provider.load()
        state["operations"][self.operation_id] = operation
        self.harness.provider.save(state)
        shutil.rmtree(self.harness.provider.root / "history")
        return operation

    def test_legacy_inline_preview_and_archive_creation_keep_live_provider_state(self):
        operation = self.legacy_inline()
        before = self.files()
        state = (self.harness.provider.root / "state.json").read_bytes()
        preview = self.compact(False)
        self.assertEqual(preview["operation_sha256"], job.hash_bytes(job.encode(operation)))
        self.assertEqual(before, self.files())
        self.assertFalse((self.harness.provider.root / "history").exists())
        self.assertEqual(self.compact(), preview)
        self.assertEqual((self.harness.provider.root / "state.json").read_bytes(), state)
        archived = self.harness.provider.archived_operation(self.operation_id, preview["controller_id"])
        self.assertEqual(archived, operation)
        self.assertEqual(self.compact(), preview)

    def test_legacy_restart_after_provider_archive_before_marker_keeps_all_authority(self):
        self.legacy_inline()
        before, state = self.files(), (self.harness.provider.root / "state.json").read_bytes()
        atomic = sentry.atomic_json
        def interrupted(path, value):
            if Path(path) == self.marker:
                raise KeyboardInterrupt()
            atomic(path, value)
        with patch.object(sentry, "atomic_json", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.compact()
        self.assertEqual(before, self.files())
        self.assertEqual((self.harness.provider.root / "state.json").read_bytes(), state)
        self.assertTrue((self.harness.provider.root / "history" / ("operation-" + self.operation_id + ".json")).is_file())
        self.compact()
        self.assertEqual((self.harness.provider.root / "state.json").read_bytes(), state)

    def test_existing_marker_cannot_rebuild_missing_provider_history(self):
        controller = self.harness.instance.controller()
        operation = copy.deepcopy(controller.operation(self.operation_id))
        self.compact()
        state = self.harness.provider.load()
        state["operations"][self.operation_id] = operation
        self.harness.provider.save(state)
        shutil.rmtree(self.harness.provider.root / "history")
        before = self.files()
        with self.assertRaisesRegex(runpod.Error, "history_missing_or_changed"):
            self.compact()
        self.assertEqual(before, self.files())


if __name__ == "__main__":
    unittest.main()
