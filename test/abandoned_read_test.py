import unittest
from unittest.mock import MagicMock

from at_client.connections.atconnection import AtConnection
from at_client.connections.response import Response


class _TestConnection(AtConnection):
    """Minimal concrete subclass so the base execute_command can be exercised."""

    def parse_raw_response(self, raw_response):
        text = raw_response.strip().rstrip('@')
        return Response().set_raw_data_response(text[len('data:'):]
                                                if text.startswith('data:') else text)


class AbandonedReadTest(unittest.TestCase):
    """A command whose reply is not read leaves that reply queued on the socket.

    If the connection is reused, the next command receives the previous command's
    answer and every command after it is one reply behind — so a lookup can return a
    completely different record's value. The connection must therefore be discarded.
    """

    def _connection(self, read_side_effect):
        connection = _TestConnection.__new__(_TestConnection)
        connection._connected = True
        connection._verbose = False
        socket = MagicMock()
        socket.read.side_effect = read_side_effect
        connection._secure_root_socket = socket
        return connection

    def test_abandoned_read_discards_the_connection(self):
        connection = self._connection(TimeoutError('The read operation timed out'))
        with self.assertRaises(TimeoutError):
            connection.execute_command('llookup:shared_key.bob@alice')
        self.assertFalse(connection.is_connected(),
                         'a connection with an unread reply must not be reused')

    def test_successful_command_keeps_the_connection(self):
        connection = self._connection([b'data:ok\n'])
        response = connection.execute_command('llookup:phone.wavi@alice')
        self.assertEqual(response.get_raw_data_response(), 'ok')
        self.assertTrue(connection.is_connected())

    def test_command_that_reads_no_reply_is_unaffected(self):
        """`monitor` and `noop` are sent without reading a reply here."""
        connection = self._connection(TimeoutError('should never be read'))
        self.assertEqual(connection.execute_command('noop:0', read_the_response=False), '')
        self.assertTrue(connection.is_connected())


if __name__ == '__main__':
    unittest.main()
