import base64
import unittest
from unittest.mock import MagicMock, patch

from at_client import AtClient
from at_client.atclient import LEGACY_IV
from at_client.common import AtSign
from at_client.common.keys import SelfKey, SharedKey
from at_client.common.metadata import Metadata
from at_client.util.encryptionutil import EncryptionUtil
from at_client.util.keysutil import KeysUtil


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

    def test_put_self_key_generates_and_persists_iv(self):
        client = AtClient.__new__(AtClient)
        me = AtSign("@alice")
        client.atsign = me
        client.keys = {
            KeysUtil.self_encryption_key_name: EncryptionUtil.generate_aes_key_base64(),
            KeysUtil.encryption_private_key_name: "x",  # sign is patched below; value unused
        }
        sent = {}
        resp = MagicMock()
        resp.get_raw_data_response.return_value = "data:ok"

        def _exec(command, *a, **k):
            sent["command"] = command
            return resp
        client.secondary_connection = MagicMock()
        client.secondary_connection.execute_command.side_effect = _exec

        key = SelfKey("selfdemo", me)
        key.set_namespace("test")
        with patch("at_client.atclient.EncryptionUtil.sign_sha256_rsa", return_value="sig"):
            client._put_self_key(key, "self secret")

        self.assertEqual(len(key.metadata.iv_nonce), 16)           # random IV generated
        b64 = base64.b64encode(key.metadata.iv_nonce).decode()
        self.assertIn(f":ivNonce:{b64}", sent["command"])          # persisted via UpdateVerbBuilder

    def test_put_layer_generates_iv_before_dispatch(self):
        """put() itself sets the IV (like Dart's _putInternal), before the encryptor."""
        client = AtClient.__new__(AtClient)
        client._put_shared_key = MagicMock(return_value="ok")
        client._put_self_key = MagicMock(return_value="ok")
        me = AtSign("@alice")

        sk = SharedKey("k", me, AtSign("@bob"))
        sk.set_namespace("test")
        self.assertIsNone(sk.metadata.iv_nonce)
        client.put(sk, "v")
        self.assertEqual(len(sk.metadata.iv_nonce), 16)
        client._put_shared_key.assert_called_once()

        selfk = SelfKey("k", me)
        selfk.set_namespace("test")
        self.assertIsNone(selfk.metadata.iv_nonce)
        client.put(selfk, "v")
        self.assertEqual(len(selfk.metadata.iv_nonce), 16)
        client._put_self_key.assert_called_once()

    def test_self_key_roundtrip_with_random_iv(self):
        """Encrypt as put-self does, then decrypt as get-self does — via ivNonce."""
        self_key = EncryptionUtil.generate_aes_key_base64()
        iv = EncryptionUtil.generate_iv_nonce()
        cipher = EncryptionUtil.aes_encrypt_from_base64("self value", self_key, iv)

        client = AtClient.__new__(AtClient)
        client.secondary_connection = None  # silence __del__ during GC
        client.keys = {KeysUtil.self_encryption_key_name: self_key}
        fetched = {"key": "selfdemo.test@alice", "data": cipher,
                   "metaData": {"ivNonce": base64.b64encode(iv).decode()}}
        client.get_lookup_response = MagicMock(return_value=fetched)

        k = SelfKey("selfdemo", AtSign("@alice"))
        k.set_namespace("test")
        self.assertEqual(client._get_self_key(k), "self value")


if __name__ == "__main__":
    unittest.main()
