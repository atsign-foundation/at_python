import unittest
import socket
from at_client.common import AtSign
from at_client.connections import AtRootConnection, AtSecondaryConnection, Response


class AtSecondaryConnectionTest(unittest.TestCase):
    verbose = False

    def test_secondary_connection(self):
        """
        Test secondary connection establishment.
        """
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_connection = AtSecondaryConnection(secondary_address, verbose=self.verbose)
        secondary_connection.connect()
        self.assertTrue(secondary_connection.is_connected())
        secondary_connection.disconnect()

    def test_multiple_secondary_connections(self):
        """
        Test multiple secondary connections.
        """
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        secondary_address1 = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_connection1 = AtSecondaryConnection(secondary_address1, verbose=self.verbose)
        secondary_connection1.connect()
        secondary_address2 = root_connection.find_secondary(AtSign("@19total67"))
        secondary_connection2 = AtSecondaryConnection(secondary_address2, verbose=self.verbose)
        secondary_connection2.connect()
        secondary_address3 = root_connection.find_secondary(AtSign("@wildgreen"))
        secondary_connection3 = AtSecondaryConnection(secondary_address3, verbose=self.verbose)
        secondary_connection3.connect()
        secondary_address4 = root_connection.find_secondary(AtSign("@colin"))
        secondary_connection4 = AtSecondaryConnection(secondary_address4, verbose=self.verbose)
        secondary_connection4.connect()

        self.assertIsNotNone(secondary_connection1)
        self.assertIsNotNone(secondary_connection2)
        self.assertIsNotNone(secondary_connection3)
        self.assertIsNotNone(secondary_connection4)
        secondary_connection1.disconnect()
        secondary_connection2.disconnect()
        secondary_connection3.disconnect()
        secondary_connection4.disconnect()

    def test_parse_raw_response_data(self):
        raw_response = "data:response_data\n"
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
        at_secondary_connection = AtSecondaryConnection(secondary_address, self.verbose)
        response = at_secondary_connection.parse_raw_response(raw_response)

        # Verify that the response is parsed correctly
        self.assertIsInstance(response, Response)
        self.assertEqual(response.get_raw_data_response(), "response_data")

        raw_response = "error:AT1234-UnknownError :response_error\n"
        response = at_secondary_connection.parse_raw_response(raw_response)
        self.assertEqual(response.get_raw_error_response(), "AT1234-UnknownError :response_error")

        raw_response = "invalid_response\n"
        with self.assertRaises(ValueError):
            at_secondary_connection.parse_raw_response(raw_response)


if __name__ == '__main__':
    unittest.main()
