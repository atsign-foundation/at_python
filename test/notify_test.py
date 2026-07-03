import inspect
import unittest
from unittest.mock import MagicMock

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import SharedKey
from at_client.util import EncryptionUtil


class NotifyTest(unittest.TestCase):
    """Network-free regression tests for AtClient.notify()."""

    def test_session_id_default_is_none(self):
        """The session_id default must not bake in a single UUID at import time.

        A signature default of str(uuid.uuid4()) is evaluated once, so every notify()
        without an explicit session_id reuses it and the server dedups/drops repeats.
        """
        default = inspect.signature(AtClient.notify).parameters["session_id"].default
        self.assertIsNone(default)

    def _mock_client(self):
        client = AtClient.__new__(AtClient)  # bypass the network-connecting __init__
        client.queue = None
        client.get_encryption_key_shared_by_me = MagicMock(
            return_value=EncryptionUtil.generate_aes_key_base64()
        )
        resp = MagicMock()
        resp.get_raw_data_response.return_value = "data:ok"
        client.secondary_connection = MagicMock()
        client.secondary_connection.execute_command.return_value = resp
        return client

    def test_notify_generates_iv_nonce_when_unset(self):
        """notify() must generate an AES nonce when the key has none (else it crashes)."""
        client = self._mock_client()
        key = SharedKey("demo", AtSign("@alice"), AtSign("@bob"))
        key.set_namespace("test")
        self.assertIsNone(key.metadata.iv_nonce)

        result = client.notify(key, "hello")  # must not raise

        self.assertIsNotNone(key.metadata.iv_nonce)  # generated and set on the key
        self.assertEqual(result, "data:ok")

    def test_notify_uses_fresh_nonce_per_call(self):
        """A reused AtKey must get a fresh nonce each call (no AES-CTR nonce reuse)."""
        client = self._mock_client()
        key = SharedKey("demo", AtSign("@alice"), AtSign("@bob"))
        key.set_namespace("test")

        client.notify(key, "hello")
        first = key.metadata.iv_nonce
        client.notify(key, "hello again")   # same key instance, already has an ivNonce
        second = key.metadata.iv_nonce

        self.assertIsNotNone(first)
        self.assertNotEqual(first, second)  # fresh nonce, not the previous one


if __name__ == "__main__":
    unittest.main()
