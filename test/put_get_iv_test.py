import base64
import unittest
from unittest.mock import MagicMock

from at_client import AtClient
from at_client.atclient import LEGACY_IV
from at_client.common import AtSign
from at_client.common.keys import SharedKey
from at_client.common.metadata import Metadata
from at_client.util.encryptionutil import EncryptionUtil


class PutGetIVTest(unittest.TestCase):
    """Network-free tests for random-IV put/get (Dart-matched behavior)."""

    def test_aes_roundtrip_with_random_iv(self):
        key = EncryptionUtil.generate_aes_key_base64()
        iv = EncryptionUtil.generate_iv_nonce()
        enc = EncryptionUtil.aes_encrypt_from_base64("hello world", key, iv)
        dec = EncryptionUtil.aes_decrypt_from_base64(enc.encode(), key, iv)
        self.assertEqual(dec, "hello world")

    def test_legacy_zero_iv_is_16_bytes(self):
        self.assertEqual(LEGACY_IV, b"\x00" * 16)

    def test_metadata_iv_nonce_bytes_roundtrip(self):
        iv = EncryptionUtil.generate_iv_nonce()  # bytes
        md = Metadata()
        md.iv_nonce = iv
        # __str__ emits base64
        b64 = base64.b64encode(iv).decode()
        self.assertIn(f":ivNonce:{b64}", str(md))
        # from_json decodes base64 back to the SAME bytes
        parsed = Metadata.from_json(f'{{"ivNonce":"{b64}"}}')
        self.assertEqual(parsed.iv_nonce, iv)

    def test_iv_from_fetched(self):
        iv = EncryptionUtil.generate_iv_nonce()
        b64 = base64.b64encode(iv).decode()
        self.assertEqual(AtClient._iv_from_fetched({"metaData": {"ivNonce": b64}}), iv)
        self.assertEqual(AtClient._iv_from_fetched({"metaData": {}}), LEGACY_IV)
        self.assertEqual(AtClient._iv_from_fetched({}), LEGACY_IV)

    def test_put_shared_key_generates_and_persists_iv(self):
        client = AtClient.__new__(AtClient)
        me = AtSign("@alice")
        client.atsign = me
        client.get_encryption_key_shared_by_me = MagicMock(
            return_value=EncryptionUtil.generate_aes_key_base64())
        sent = {}
        resp = MagicMock()
        resp.get_raw_data_response.return_value = "data:ok"

        def _exec(command, *a, **k):
            sent["command"] = command
            return resp
        client.secondary_connection = MagicMock()
        client.secondary_connection.execute_command.side_effect = _exec

        key = SharedKey("demo", me, AtSign("@bob"))
        key.set_namespace("test")
        self.assertIsNone(key.metadata.iv_nonce)

        client._put_shared_key(key, "secret")

        self.assertIsInstance(key.metadata.iv_nonce, (bytes, bytearray))
        self.assertEqual(len(key.metadata.iv_nonce), 16)          # random 16-byte IV
        b64 = base64.b64encode(key.metadata.iv_nonce).decode()
        self.assertIn(f":ivNonce:{b64}", sent["command"])          # persisted in update cmd


if __name__ == "__main__":
    unittest.main()
