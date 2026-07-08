import unittest
from queue import Queue
from unittest.mock import patch

from at_client import AtClient
from at_client.common import AtSign
from at_client.connections.address import Address
from at_client.connections.atmonitorconnection import AtMonitorConnection


class MonitorResumeTest(unittest.TestCase):
    """Network-free tests for seeding the monitor resume position.

    The monitor verb is `monitor:<epochMillis> <regex>`: the server replays
    notifications received after epochMillis. Before this change
    last_received_time could not be seeded, so a caller that rebuilt its client
    after a dropped monitor always sent `monitor:0` instead of resuming.
    """

    def _connection(self, **kwargs):
        with patch.object(AtMonitorConnection, "start_heart_beat"):
            return AtMonitorConnection(queue=Queue(), atsign=AtSign("@alice"),
                                       address=Address("localhost", 64),
                                       verbose=False, regex="test", **kwargs)

    def test_default_starts_from_zero(self):
        conn = self._connection()
        self.assertEqual(conn.last_received_time, 0)
        self.assertEqual(conn._build_monitor_command(), "monitor:0 test")

    def test_seeded_position_is_used_in_monitor_command(self):
        conn = self._connection(last_received_time=1720000000000)
        self.assertEqual(conn._build_monitor_command(), "monitor:1720000000000 test")

    def test_atclient_start_monitor_passes_seed_through(self):
        client = AtClient.__new__(AtClient)  # bypass the network-connecting __init__
        client.queue = Queue()
        client.monitor_connection = None
        client.atsign = AtSign("@alice")
        client.secondary_address = Address("localhost", 64)
        client.verbose = False
        client.keys = {}
        with patch("at_client.atclient.AtMonitorConnection") as connection_cls, \
                patch("at_client.atclient.AuthUtil.authenticate_with_pkam"):
            connection_cls.return_value.running = True  # skip start_monitor() on the mock
            client.start_monitor("test", last_received_time=42)
        self.assertEqual(connection_cls.call_args.kwargs["last_received_time"], 42)


if __name__ == "__main__":
    unittest.main()
