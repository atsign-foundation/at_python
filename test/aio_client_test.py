import base64
import json
import unittest

from at_client.aio.atclient import AsyncAtClient, LEGACY_IV
from at_client.aio.connection import AsyncAtConnection
from at_client.util import EncryptionUtil


def _client_with_cached_shared_key(sender: str, aes_key: str) -> AsyncAtClient:
    client = AsyncAtClient.__new__(AsyncAtClient)  # bypass the network-connecting create()
    client.verbose = False
    client._shared_key_cache = {sender: aes_key}
    return client


def _notification_line(value: str, aes_key: str, iv: bytes = None) -> bytes:
    metadata = {}
    if iv is not None:
        metadata["ivNonce"] = base64.b64encode(iv).decode()
    encrypted = EncryptionUtil.aes_encrypt_from_base64(value, aes_key, iv if iv is not None else LEGACY_IV)
    data = {"id": "abc", "from": "@bob", "to": "@alice", "key": "@alice:demo.test@bob",
            "operation": "update", "epochMillis": 1720000000000, "value": encrypted,
            "isEncrypted": True, "metadata": metadata}
    return b"notification: " + json.dumps(data).encode() + b"\n"


class AioClientTest(unittest.IsolatedAsyncioTestCase):
    """Network-free tests for the asyncio client's parsing and decryption."""

    def test_parse_monitor_line(self):
        client = _client_with_cached_shared_key("@bob", EncryptionUtil.generate_aes_key_base64())
        line = _notification_line("hi", EncryptionUtil.generate_aes_key_base64())
        notification = client._parse_monitor_line(line)
        self.assertEqual(notification.from_atsign, "@bob")
        self.assertEqual(notification.operation, "update")
        self.assertEqual(notification.epoch_millis, 1720000000000)

    def test_parse_monitor_line_tolerates_prompt_remnant(self):
        client = _client_with_cached_shared_key("@bob", EncryptionUtil.generate_aes_key_base64())
        line = b"@alice@" + _notification_line("hi", EncryptionUtil.generate_aes_key_base64())
        self.assertIsNotNone(client._parse_monitor_line(line))

    def test_parse_monitor_line_ignores_heartbeat_ack(self):
        client = _client_with_cached_shared_key("@bob", EncryptionUtil.generate_aes_key_base64())
        self.assertIsNone(client._parse_monitor_line(b"data:ok\n"))

    async def test_decrypt_with_iv_nonce(self):
        aes_key = EncryptionUtil.generate_aes_key_base64()
        iv = EncryptionUtil.generate_iv_nonce()
        client = _client_with_cached_shared_key("@bob", aes_key)
        notification = client._parse_monitor_line(_notification_line("secret value", aes_key, iv))
        await client._decrypt(notification)
        self.assertTrue(notification.decrypted)
        self.assertEqual(notification.value, "secret value")

    async def test_decrypt_legacy_zero_iv(self):
        aes_key = EncryptionUtil.generate_aes_key_base64()
        client = _client_with_cached_shared_key("@bob", aes_key)
        notification = client._parse_monitor_line(_notification_line("legacy value", aes_key))
        await client._decrypt(notification)
        self.assertTrue(notification.decrypted)
        self.assertEqual(notification.value, "legacy value")

    def test_response_parsing_matches_sync_rules(self):
        response = AsyncAtConnection._parse("data:hello\n@alice@")
        self.assertEqual(response.get_raw_data_response(), "hello")
        response = AsyncAtConnection._parse("error:AT0015-key not found : nope@")
        self.assertTrue(response.is_error())
        self.assertEqual(response.get_error_code(), "AT0015")


if __name__ == "__main__":
    unittest.main()
