from collections import deque
import errno
import os
import signal
import unittest
from unittest.mock import patch

import fri_session


class AdoptedProcesses:
    def __init__(self, wait_errors=(), scans=()):
        self.live, self.zombies, self.reaped = {201, 202}, deque(), set()
        self.wait_errors, self.scans = deque(wait_errors), deque(scans)
        self.observed_echild, self.polls = False, 0

    def waitpid(self, pid, options):
        assert (pid, options) == (-1, os.WNOHANG)
        self.polls += 1
        assert self.polls < 100, "guardian failed to finish cleanup after children became reapable"
        if self.wait_errors:
            number = self.wait_errors.popleft()
            raise OSError(number, "temporary wait failure")
        if self.zombies:
            child = self.zombies.popleft()
            self.reaped.add(child)
            return child, 0
        if self.live:
            return 0, 0
        self.observed_echild = True
        raise ChildProcessError(errno.ECHILD, "all adopted children reaped")

    def children(self):
        scan = self.scans.popleft() if self.scans else "complete"
        if isinstance(scan, OSError):
            raise scan
        if scan == "empty":
            return
        for child in sorted(self.live):
            yield child
            if scan == "partial":
                raise OSError(errno.EIO, "proc iterator failed after yielding a child")

    def kill(self, pid, signum):
        assert signum == signal.SIGKILL
        self.live.remove(pid)
        self.zombies.append(pid)


class GuardianRetryTests(unittest.TestCase):
    def reap(self, processes):
        with patch.object(fri_session.os, "waitpid", side_effect=processes.waitpid), \
                patch.object(fri_session.os, "kill", side_effect=processes.kill), \
                patch.object(fri_session, "_adopted_children", side_effect=processes.children), \
                patch.object(fri_session.time, "sleep"):
            fri_session._reap_adopted_children()
        self.assertTrue(processes.observed_echild, "cleanup returned before the kernel proved there were no children")
        self.assertEqual(processes.reaped, {201, 202})
        self.assertFalse(processes.live)
        self.assertFalse(processes.zombies)

    def test_waitpid_interruption_and_transient_errors_do_not_release_live_children(self):
        processes = AdoptedProcesses(wait_errors=(errno.EINTR, errno.EAGAIN, errno.EIO))
        self.reap(processes)
        self.assertFalse(processes.wait_errors)

    def test_empty_failed_and_partial_discovery_waits_for_all_children_to_be_reaped(self):
        processes = AdoptedProcesses(scans=(PermissionError(errno.EACCES, "proc unavailable"),
            FileNotFoundError(errno.ENOENT, "proc changed"), "empty", "partial", "empty"))
        self.reap(processes)
        self.assertFalse(processes.scans)


if __name__ == "__main__":
    unittest.main()
