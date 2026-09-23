import asyncio
import ssl

from ..connections.address import Address
from ..connections.response import Response
from ..exception.atexception import AtException


class AsyncAtConnection:
    """An asyncio connection to an atServer, speaking the same wire protocol as
    the synchronous AtConnection: commands are newline-terminated, responses end
    at the server's '@' prompt or a newline."""

    def __init__(self, address: Address, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, verbose: bool = False):
        self.address = address
        self._reader = reader
        self._writer = writer
        self._verbose = verbose
        self._command_lock = asyncio.Lock()

    @classmethod
    async def connect(cls, address: Address, context: ssl.SSLContext = None,
                      verbose: bool = False) -> "AsyncAtConnection":
        context = context or ssl.create_default_context()
        reader, writer = await asyncio.open_connection(address.host, address.port, ssl=context)
        connection = cls(address, reader, writer, verbose)
        await connection._read_frame()  # consume the server's initial '@' prompt
        return connection

    async def write(self, data: str):
        self._writer.write(data.encode())
        await self._writer.drain()

    async def readline(self) -> bytes:
        """Read one newline-terminated line (used by the monitor stream)."""
        return await self._reader.readline()

    async def _read_frame(self) -> str:
        """Accumulate until the '@' prompt or a newline, as AtConnection.read does."""
        response = b""
        while True:
            chunk = await self._reader.read(1024)
            if chunk == b"":
                raise ConnectionError(f"connection to {self.address} closed by peer")
            response += chunk
            if chunk == b"@" or b"\n" in chunk:
                return response.decode()

    async def execute_command(self, command: str, raise_exception: bool = True) -> Response:
        """Send one command and parse its response (same rules as the sync client)."""
        if not command.endswith("\n"):
            command += "\n"
        async with self._command_lock:
            await self.write(command)
            if self._verbose:
                print(f"\tSENT: {command.strip()!r}")
            raw = await self._read_frame()
        if self._verbose:
            print(f"\tRCVD: {raw!r}")
        response = self._parse(raw)
        if response.is_error() and raise_exception:
            raise response.get_exception()
        return response

    @staticmethod
    def _parse(raw: str) -> Response:
        if raw.endswith("@"):
            raw = raw[:-1]
        raw = raw.strip()
        data_index = raw.find("data:")
        error_index = raw.find("error:")
        if data_index > -1:
            return Response().set_raw_data_response(raw[data_index + len("data:"):].split("\n")[0])
        if error_index > -1:
            return Response().set_raw_error_response(raw[error_index + len("error:"):])
        raise AtException(f"Invalid response from server: {raw}")

    async def close(self):
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass


async def find_secondary(atsign, root_address: Address,
                         context: ssl.SSLContext = None, verbose: bool = False) -> Address:
    """Look up an atSign's secondary address on the root server.

    The root speaks a bare protocol: send the atSign without its '@' prefix,
    receive 'host:port' (or 'null' when the atSign is not found).
    """
    context = context or ssl.create_default_context()
    reader, writer = await asyncio.open_connection(root_address.host, root_address.port, ssl=context)
    try:
        await reader.readuntil(b"@")  # initial prompt
        writer.write((atsign.without_prefix + "\n").encode())
        await writer.drain()
        raw = (await reader.readuntil(b"@")).decode()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    response = raw.strip().rstrip("@").strip()
    if verbose:
        print(f"\troot lookup {atsign}: {response!r}")
    if response == "null":
        raise AtException(f"Root lookup returned null for {atsign}")
    return Address.from_string(response)
