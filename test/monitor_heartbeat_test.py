import unittest
from queue import Queue

from at_client.common import AtSign
from at_client.connections.address import Address
from at_client.connections.atmonitorconnection import AtMonitorConnection


class MonitorHeartbeatTest(unittest.TestCase):
    """Network-free tests for heartbeat thread lifecycle and per-instance locks."""

    def _connection(self):
        return AtMonitorConnection(queue=Queue(), atsign=AtSign("@alice"),
                                   address=Address("localhost", 64), verbose=False)

    def test_heartbeat_thread_is_daemon(self):
        """A non-daemon heartbeat thread would keep the process alive forever."""
        conn = self._connection()
        self.assertTrue(conn._heartbeat_thread.daemon)

    def test_locks_are_per_instance(self):
        """Module-level locks made every monitor in a process share one lock pair."""
        a = self._connection()
        b = self._connection()
        self.assertIsNot(a.should_be_running_lock, b.should_be_running_lock)
        self.assertIsNot(a.running_lock, b.running_lock)

    def test_one_connections_lock_does_not_block_another(self):
        a = self._connection()
        b = self._connection()
        with a.should_be_running_lock:
            self.assertTrue(b.should_be_running_lock.acquire(blocking=False))
            b.should_be_running_lock.release()

    def test_stop_heart_beat_ends_the_thread(self):
        """The heartbeat loop must exit promptly when stopped, not at process exit."""
        conn = self._connection()
        self.assertTrue(conn._heartbeat_thread.is_alive())
        conn.stop_heart_beat()
        conn._heartbeat_thread.join(timeout=2)
        self.assertFalse(conn._heartbeat_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
