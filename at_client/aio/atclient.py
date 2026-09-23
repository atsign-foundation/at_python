import asyncio
import base64
import json
import ssl
import uuid
from dataclasses import dataclass, field

from ..common.atsign import AtSign
from ..common.keys import SharedKey
from ..connections.address import Address
from ..exception.atexception import AtKeyNotFoundException, AtUnauthenticatedException
from ..util.encryptionutil import EncryptionUtil
from ..util.keysutil import KeysUtil
from ..util.verbbuilder import FromVerbBuilder, NotifyVerbBuilder, OperationEnum, PKAMVerbBuilder
from .connection import AsyncAtConnection, find_secondary

LEGACY_IV = b"\x00" * 16


@dataclass
class AtNotification:
    """One decrypted notification from the monitor stream."""
    id: str
    key: str
    from_atsign: str
    to_atsign: str
    operation: str
    epoch_millis: int
    value: str | None
    decrypted: bool
    raw: dict = field(repr=False)


class AsyncAtClient:
    """asyncio atProtocol client: PKAM auth, encrypted notify, and a monitor
    exposed as an async iterator.

    Proof of concept. Reuses the synchronous SDK's crypto, key handling and verb
    builders (all I/O-free); only the connection layer is new. Create with::

        client = await AsyncAtClient.create("@alice")
        async for notification in client.monitor(regex="my_namespace"):
            ...
    """

    def __init__(self, atsign: AtSign, keys: dict, secondary_address: Address,
                 connection: AsyncAtConnection, verbose: bool = False):
        self.atsign = atsign
        self.keys = keys
        self.secondary_address = secondary_address
        self.connection = connection
        self.verbose = verbose
        self._shared_key_cache: dict = {}

    @classmethod
    async def create(cls, atsign: str, root_address: Address = Address("root.atsign.org", 64),
                     secondary_address: Address = None, context: ssl.SSLContext = None,
                     verbose: bool = False) -> "AsyncAtClient":
        at = AtSign(atsign)
        keys = KeysUtil.load_keys(at)
        if secondary_address is None:
            secondary_address = await find_secondary(at, root_address, context, verbose)
        connection = await AsyncAtConnection.connect(secondary_address, context, verbose)
        client = cls(at, keys, secondary_address, connection, verbose)
        await client._authenticate(connection)
        return client

    async def _authenticate(self, connection: AsyncAtConnection):
        challenge = (await connection.execute_command(
            FromVerbBuilder().set_shared_by(self.atsign).build())).get_raw_data_response()
        signature = EncryptionUtil.sign_sha256_rsa(challenge, self.keys[KeysUtil.pkam_private_key_name])
        response = await connection.execute_command(PKAMVerbBuilder().set_digest(signature).build())
        if response.get_raw_data_response() != "success":
            raise AtUnauthenticatedException(f"PKAM failed: {response}")

    # ---------------------------------------------------------------- notify
    async def notify(self, to: str, key_name: str, value: str,
                     namespace: str = None, ttl_ms: int = 60000) -> str:
        """Encrypt value to `to` and send it as an update notification."""
        at_key = SharedKey(key_name, self.atsign, AtSign(to))
        if namespace:
            at_key.set_namespace(namespace)
        at_key.set_time_to_live(ttl_ms)
        iv = EncryptionUtil.generate_iv_nonce()
        at_key.metadata.iv_nonce = iv
        shared_key = await self._encryption_key_shared_by_me(at_key)
        encrypted = EncryptionUtil.aes_encrypt_from_base64(value, shared_key, iv)
        command = NotifyVerbBuilder().with_at_key(
            at_key, encrypted, OperationEnum.UPDATE, session_id=str(uuid.uuid4())).build()
        return (await self.connection.execute_command(command)).get_raw_data_response()

    async def _encryption_key_shared_by_me(self, at_key: SharedKey) -> str:
        """Fetch (or create, on first contact) the AES key we share with the recipient."""
        to_lookup = "shared_key." + at_key.shared_with.without_prefix + self.atsign.to_string()
        response = await self.connection.execute_command("llookup:" + to_lookup, raise_exception=False)
        if not response.is_error():
            return EncryptionUtil.rsa_decrypt_from_base64(
                response.get_raw_data_response(), self.keys[KeysUtil.encryption_private_key_name])
        if not isinstance(response.get_exception(), AtKeyNotFoundException):
            raise response.get_exception()
        their_public = (await self.connection.execute_command(
            "plookup:publickey" + at_key.shared_with.to_string())).get_raw_data_response()
        aes_key = EncryptionUtil.generate_aes_key_base64()
        for_us = EncryptionUtil.rsa_encrypt_to_base64(aes_key, self.keys[KeysUtil.encryption_public_key_name])
        for_them = EncryptionUtil.rsa_encrypt_to_base64(aes_key, their_public)
        await self.connection.execute_command("update:" + to_lookup + " " + for_us)
        await self.connection.execute_command(
            "update:ttr:86400000:" + at_key.shared_with.to_string() + ":shared_key"
            + self.atsign.to_string() + " " + for_them)
        return aes_key

    async def _encryption_key_shared_by_other(self, sender: str) -> str:
        """Fetch (and cache) the AES key `sender` shared with us, for decrypting."""
        if sender in self._shared_key_cache:
            return self._shared_key_cache[sender]
        response = await self.connection.execute_command("lookup:shared_key" + sender)
        key = EncryptionUtil.rsa_decrypt_from_base64(
            response.get_raw_data_response(), self.keys[KeysUtil.encryption_private_key_name])
        self._shared_key_cache[sender] = key
        return key

    # --------------------------------------------------------------- monitor
    async def monitor(self, regex: str = ".*", last_received_time: int = 0,
                      heartbeat_interval_s: float = 30.0, reconnect_delay_s: float = 3.0):
        """Yield AtNotifications forever; reconnects and resumes automatically.

        Cancelling the consuming task stops the heartbeat and closes the
        connection. `last_received_time` seeds the first monitor command; after
        that the stream resumes from the newest notification it has processed.
        """
        last = last_received_time
        while True:
            connection = None
            heartbeat = None
            try:
                connection = await AsyncAtConnection.connect(
                    self.secondary_address, verbose=self.verbose)
                await self._authenticate(connection)
                await connection.write(f"monitor:{last} {regex}\n")
                heartbeat = asyncio.create_task(self._heartbeat(connection, heartbeat_interval_s))
                async for notification in self._stream(connection, 3 * heartbeat_interval_s):
                    if notification.epoch_millis > last:
                        last = notification.epoch_millis
                    if notification.id == "-1":
                        continue  # server stats notification
                    if notification.operation == "update":
                        await self._decrypt(notification)
                    yield notification
            except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, OSError) as e:
                if self.verbose:
                    print(f"[monitor {self.atsign}] {type(e).__name__}: {e}; reconnecting")
            finally:
                if heartbeat is not None:
                    heartbeat.cancel()
                if connection is not None:
                    await connection.close()
            await asyncio.sleep(reconnect_delay_s)

    async def _stream(self, connection: AsyncAtConnection, read_timeout_s: float):
        """Yield parsed notifications from one monitor connection until EOF.

        The read timeout bounds a silently dead socket: heartbeat acks arrive
        every interval, so a read that outlives three of them means the
        connection is gone even if the OS never reports it.
        """
        while True:
            line = await asyncio.wait_for(connection.readline(), timeout=read_timeout_s)
            if line == b"":
                return  # EOF: server closed the connection
            notification = self._parse_monitor_line(line)
            if notification is not None:
                yield notification

    async def _heartbeat(self, connection: AsyncAtConnection, interval_s: float):
        """Keep the monitor connection alive; its 'data:ok' acks are read (and
        discarded) by the monitor loop, which also times out if they stop."""
        while True:
            await asyncio.sleep(interval_s)
            await connection.write("noop:0\n")

    def _parse_monitor_line(self, line: bytes) -> AtNotification | None:
        index = line.find(b"notification:")
        if index < 0:
            return None  # heartbeat ack, prompt remnant, or blank
        data = json.loads(line[index + len(b"notification:"):].decode())
        return AtNotification(
            id=str(data.get("id")),
            key=str(data.get("key")),
            from_atsign=str(data.get("from")),
            to_atsign=str(data.get("to")),
            operation=str(data.get("operation")),
            epoch_millis=int(data.get("epochMillis", 0)),
            value=None,
            decrypted=False,
            raw=data,
        )

    async def _decrypt(self, notification: AtNotification):
        """Decrypt in place; on failure the notification is yielded undecrypted."""
        encrypted = notification.raw.get("value")
        if encrypted is None:
            return
        metadata = notification.raw.get("metadata") or {}
        iv_b64 = metadata.get("ivNonce")
        iv = base64.b64decode(iv_b64) if iv_b64 else LEGACY_IV
        try:
            shared_key = await self._encryption_key_shared_by_other(notification.from_atsign)
            notification.value = EncryptionUtil.aes_decrypt_from_base64(
                encrypted.encode(), shared_key, iv)
            notification.decrypted = True
        except Exception as e:
            if self.verbose:
                print(f"[monitor {self.atsign}] could not decrypt {notification.key}: {e}")

    async def close(self):
        await self.connection.close()
