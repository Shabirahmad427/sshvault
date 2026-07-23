"""Display-free adapter tests for TrustDecisionBroker."""

from __future__ import annotations
import os
import tempfile
import threading
import unittest

os.environ["HOME"] = tempfile.mkdtemp(prefix="sshvault-test-home-")
from sshvault import TrustDecisionBroker
from sshvault_security import HostKeyTrustRequest, ChangedHostKeyRequest, TrustDecision


class FakeRoot:
    def __init__(self):
        self.callbacks = []
        self.dead = False

    def after(self, _delay, callback):
        if not self.dead:
            self.callbacks.append(callback)
        return len(self.callbacks)

    def run_next(self):
        if self.callbacks:
            self.callbacks.pop(0)()

    def run_until(self, predicate, limit=30):
        for _ in range(limit):
            if predicate():
                return
            self.run_next()
        raise AssertionError("callback limit exceeded")

    def destroy(self):
        self.dead = True

    def run_all(self, limit=100):
        for _ in range(limit):
            if not self.callbacks:
                return
            self.run_next()
        raise AssertionError("callback limit exceeded")

    @property
    def pending_count(self):
        return len(self.callbacks)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = FakeRoot()
        self.unknown = []
        self.changed = []
        self.broker = TrustDecisionBroker(
            self.root, lambda *args: self.unknown.append(args), lambda *args: self.changed.append(args)
        )
        self.unknown_request = HostKeyTrustRequest("P", "Destination host", "h", 22, "ssh-rsa", "SHA256:x")
        self.changed_request = ChangedHostKeyRequest("P", "Jump host", "j", 2200, "ssh-rsa", "SHA256:a", "SHA256:b")

    def worker(self, fn):
        result = []
        t = threading.Thread(target=lambda: result.append(fn()))
        t.start()
        return t, result

    def test_unknown_trust_once_releases_worker(self):
        t, out = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.unknown))
        payload, ident, resolve = self.unknown[0]
        resolve(TrustDecision.TRUST_ONCE)
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(out, [TrustDecision.TRUST_ONCE])

    def test_changed_acknowledgement_releases_worker(self):
        t, out = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.run_until(lambda: bool(self.changed))
        payload, ident, ack = self.changed[0]
        ack()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(out, [None])

    def test_shutdown_cancels_active_and_queued(self):
        one, a = self.worker(lambda: self.broker.request(self.unknown_request))
        two, b = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.run_until(lambda: bool(self.unknown))
        self.broker.close()
        one.join(1)
        two.join(1)
        self.assertEqual(a, [TrustDecision.CANCEL])
        self.assertFalse(two.is_alive())

    def test_stale_callback_cannot_resolve_new_request(self):
        one, a = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.unknown))
        old = self.unknown[0][2]
        old(TrustDecision.CANCEL)
        one.join(1)
        two, b = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: len(self.unknown) == 2)
        old(TrustDecision.TRUST_ONCE)
        self.assertTrue(two.is_alive())
        self.unknown[1][2](TrustDecision.CANCEL)
        two.join(1)

    def test_trust_save_and_duplicate_callback(self):
        t, out = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.unknown))
        resolve = self.unknown[0][2]
        resolve(TrustDecision.TRUST_AND_SAVE)
        resolve(TrustDecision.CANCEL)
        t.join(1)
        self.assertEqual(out, [TrustDecision.TRUST_AND_SAVE])

    def test_changed_factory_failure_releases_worker(self):
        root = FakeRoot()
        broker = TrustDecisionBroker(
            root, lambda *x: None, lambda *x: (_ for _ in ()).throw(RuntimeError("password=secret"))
        )
        t, out = self.worker(lambda: broker.warn_changed_key(self.changed_request))
        root.run_next()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(out, [None])

    def test_mixed_fifo(self):
        a, ao = self.worker(lambda: self.broker.request(self.unknown_request))
        b, bo = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.run_until(lambda: bool(self.unknown))
        self.unknown[0][2](TrustDecision.CANCEL)
        self.root.run_until(lambda: bool(self.changed))
        self.changed[0][2]()
        a.join(1)
        b.join(1)
        self.assertEqual(ao, [TrustDecision.CANCEL])
        self.assertEqual(bo, [None])

    def test_unknown_cancel_escape_and_window_close(self):
        for _action in (TrustDecision.CANCEL, TrustDecision.CANCEL, TrustDecision.CANCEL):
            count = len(self.unknown)
            t, out = self.worker(lambda: self.broker.request(self.unknown_request))
            self.root.run_until(lambda: len(self.unknown) > count)
            self.unknown[-1][2](_action)
            t.join(1)
            self.assertFalse(t.is_alive())
            self.assertEqual(out, [TrustDecision.CANCEL])

    def test_changed_duplicate_ack_and_close_releases(self):
        t, out = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.run_until(lambda: len(self.changed) > 0)
        ack = self.changed[-1][2]
        ack()
        ack()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(out, [None])

    def test_changed_then_unknown_fifo(self):
        a, ao = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        b, bo = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.changed))
        self.changed[0][2]()
        self.root.run_until(lambda: bool(self.unknown))
        self.unknown[0][2](TrustDecision.CANCEL)
        a.join(1)
        b.join(1)
        self.assertEqual((ao, bo), ([None], [TrustDecision.CANCEL]))

    def test_close_twice_is_safe(self):
        t, out = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.unknown))
        self.broker.close()
        self.broker.close()
        t.join(1)
        self.assertEqual(out, [TrustDecision.CANCEL])

    def test_close_active_changed_releases_worker(self):
        t, out = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.run_until(lambda: bool(self.changed))
        self.broker.close()
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(out, [None])
        self.assertIsNone(self.broker.active)

    def test_close_queued_unknown_workers(self):
        workers = [self.worker(lambda: self.broker.request(self.unknown_request)) for _ in range(3)]
        self.root.run_until(lambda: bool(self.unknown))
        self.broker.close()
        for thread, out in workers:
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(out, [TrustDecision.CANCEL])

    def test_root_destroy_then_close_releases_mixed_workers(self):
        unknown, uo = self.worker(lambda: self.broker.request(self.unknown_request))
        changed, co = self.worker(lambda: self.broker.warn_changed_key(self.changed_request))
        self.root.destroy()
        self.broker.close()
        unknown.join(1)
        changed.join(1)
        self.assertEqual(uo, [TrustDecision.CANCEL])
        self.assertFalse(changed.is_alive())
        self.assertEqual(self.root.pending_count, 1)

    def test_stale_callbacks_after_close_are_harmless(self):
        t, out = self.worker(lambda: self.broker.request(self.unknown_request))
        self.root.run_until(lambda: bool(self.unknown))
        stale = self.unknown[0][2]
        self.broker.close()
        stale(TrustDecision.TRUST_ONCE)
        t.join(1)
        self.assertEqual(out, [TrustDecision.CANCEL])
        self.assertIsNone(self.broker.active)
