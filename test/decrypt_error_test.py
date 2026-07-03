import unittest
from unittest.mock import MagicMock

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import SharedKey
from at_client.util.keysutil import KeysUtil
from at_client.exception.atexception import AtDecryptionException


class DecryptErrorDetailTest(unittest.TestCase):
    """The shared-key decrypt error must include the real exception, not literal 'e'."""

    def test_error_includes_exception_detail(self):
        client = AtClient.__new__(AtClient)  # bypass network __init__
        client.atsign = AtSign("@alice")
        client.keys = {KeysUtil.encryption_private_key_name: "not-a-valid-private-key"}

        resp = MagicMock()
        resp.is_error.return_value = False
        resp.get_raw_data_response.return_value = "not-valid-rsa-ciphertext"
        client.secondary_connection = MagicMock()
        client.secondary_connection.execute_command.return_value = resp

        key = SharedKey("k", AtSign("@alice"), AtSign("@bob"))
        with self.assertRaises(AtDecryptionException) as ctx:
            client.get_encryption_key_shared_by_me(key)

        msg = str(ctx.exception)
        self.assertFalse(msg.rstrip().endswith("- e"))   # the bug printed a literal 'e'
        self.assertIn("Failed to decrypt", msg)


if __name__ == "__main__":
    unittest.main()
