import unittest
from unittest.mock import MagicMock

from at_client.connections.atconnection import AtConnection


class _ConcreteConnection(AtConnection):
    """Minimal concrete subclass so we can exercise the base disconnect()."""

    def parse_raw_response(self, raw_response):
        return None


class DisconnectTest(unittest.TestCase):
    """disconnect() must always clear _connected, even if the socket close fails."""

    def test_disconnect_clears_connected_on_clean_close(self):
        conn = _ConcreteConnection.__new__(_ConcreteConnection)  # bypass network __init__
        conn._connected = True
        conn._secure_root_socket = MagicMock()
        conn.disconnect()
        conn._secure_root_socket.close.assert_called_once()
        self.assertFalse(conn._connected)

    def test_disconnect_clears_connected_even_when_close_raises(self):
        conn = _ConcreteConnection.__new__(_ConcreteConnection)
        conn._connected = True
        conn._secure_root_socket = MagicMock()
        conn._secure_root_socket.close.side_effect = OSError(9, "Bad file descriptor")
        conn.disconnect()  # must not propagate
        self.assertFalse(conn._connected)  # so the restart path can rebuild the socket


if __name__ == "__main__":
    unittest.main()
