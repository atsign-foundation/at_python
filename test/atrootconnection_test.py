import unittest
from at_client.common import AtSign
from at_client.exception import *
from at_client.connections import AtRootConnection

class AtRootConnectionTest(unittest.TestCase):
    verbose = False

    def test_root_connection_objects(self):
        """
        Test single instance of root connection.
        """
        instance1 = AtRootConnection.get_instance()
        instance2 = AtRootConnection.get_instance()
        instance3 = AtRootConnection.get_instance()

        self.assertIs(instance1, instance2)
        self.assertIs(instance2, instance3)

    def test_root_connection(self):
        """
        Test root connection establishment.
        """
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        root_connection.connect()
        self.assertTrue(root_connection.is_connected())

    def test_find_secondary(self):
        """
        Test finding a secondary server address.
        """
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        secondary_address = root_connection.find_secondary(AtSign("@27barracuda"))
        self.assertIsNotNone(secondary_address)

    def test_find_secondary_failure(self):
        """
        Test finding a secondary server address for a non-existent AtSign.
        """
        with self.assertRaises(AtSecondaryNotFoundException):
            root_connection = AtRootConnection.get_instance(verbose=self.verbose)
            root_connection.find_secondary(AtSign("@wrongAtSign"))

    def test_find_multiple_secondary_addresses(self):
        """
        Test finding multiple secondary server addresses.
        """
        root_connection = AtRootConnection.get_instance(verbose=self.verbose)
        secondary_address1 = root_connection.find_secondary(AtSign("@27barracuda"))
        secondary_address2 = root_connection.find_secondary(AtSign("@19total67"))
        secondary_address3 = root_connection.find_secondary(AtSign("@wildgreen"))
        secondary_address4 = root_connection.find_secondary(AtSign("@colin"))
        
        self.assertIsNotNone(secondary_address1)
        self.assertIsNotNone(secondary_address2)
        self.assertIsNotNone(secondary_address3)
        self.assertIsNotNone(secondary_address4)


if __name__ == '__main__':
    unittest.main()