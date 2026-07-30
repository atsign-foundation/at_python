import base64
import unittest
from unittest.mock import MagicMock

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import SharedKey
from at_client.connections.response import Response
from at_client.exception.atexception import AtDecryptionException
from at_client.util import EncryptionUtil, KeysUtil


class SharedKeyRecoveryTest(unittest.TestCase):
    """Network-free tests for recovering from a damaged stored shared key.

    A sender keeps its own copy of the AES key it shares with a recipient, encrypted
    to its own public key. If that record is damaged, every later send to the
    recipient fails on it, and restarting re-reads the same record.
    """

    @classmethod
    def setUpClass(cls):
        # generate_rsa_key_pair returns DER bytes; a keystore holds them base64-encoded,
        # which is what the RSA helpers expect.
        private_der, public_der = EncryptionUtil.generate_rsa_key_pair()
        cls.private_key = base64.b64encode(private_der).decode()
        cls.public_key = base64.b64encode(public_der).decode()
        cls.key_size_bytes = EncryptionUtil.private_key_from_base64(
            cls.private_key).key_size // 8

    def _client(self, stored_key):
        """A client whose llookup of the shared key returns `stored_key`."""
        client = AtClient.__new__(AtClient)  # bypass the network-connecting __init__
        client.atsign = AtSign("@alice")
        client.keys = {
            KeysUtil.encryption_private_key_name: self.private_key,
            KeysUtil.encryption_public_key_name: self.public_key,
        }
        client.secondary_connection = MagicMock()
        client.secondary_connection.execute_command.return_value = \
            Response().set_raw_data_response(stored_key)
        client.create_shared_encryption_key = MagicMock(return_value='replacement key')
        return client

    def _shared_key(self):
        return SharedKey('demo', AtSign('@alice'), AtSign('@bob'))

    def test_readable_stored_key_is_returned(self):
        aes_key = EncryptionUtil.generate_aes_key_base64()
        stored = EncryptionUtil.rsa_encrypt_to_base64(aes_key, self.public_key)
        client = self._client(stored)
        self.assertEqual(client.get_encryption_key_shared_by_me(self._shared_key()), aes_key)
        client.create_shared_encryption_key.assert_not_called()

    def test_wrong_length_record_is_replaced(self):
        # Not an RSA ciphertext for this key: it cannot be decrypted by anyone.
        damaged = base64.b64encode(b'truncated').decode()
        client = self._client(damaged)
        result = client.get_encryption_key_shared_by_me(self._shared_key())
        self.assertEqual(result, 'replacement key')
        client.create_shared_encryption_key.assert_called_once()

    def test_correct_length_but_undecryptable_still_raises(self):
        """Most likely the wrong keys are loaded — replacing would rotate a good key."""
        _, other_public_der = EncryptionUtil.generate_rsa_key_pair()
        stored = EncryptionUtil.rsa_encrypt_to_base64(
            EncryptionUtil.generate_aes_key_base64(),
            base64.b64encode(other_public_der).decode())
        self.assertEqual(len(base64.b64decode(stored)), self.key_size_bytes)
        client = self._client(stored)
        with self.assertRaises(AtDecryptionException):
            client.get_encryption_key_shared_by_me(self._shared_key())
        client.create_shared_encryption_key.assert_not_called()

    def test_unusable_check_is_length_based(self):
        client = self._client('unused')
        good = EncryptionUtil.rsa_encrypt_to_base64('x', self.public_key)
        self.assertFalse(client._stored_shared_key_is_unusable(good))
        self.assertTrue(client._stored_shared_key_is_unusable(
            base64.b64encode(b'short').decode()))
        # Undecidable input keeps the existing behaviour rather than replacing a key.
        self.assertFalse(client._stored_shared_key_is_unusable('not base64 !!'))


if __name__ == '__main__':
    unittest.main()
