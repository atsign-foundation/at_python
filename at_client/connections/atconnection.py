import asyncio
import socket
import ssl
from abc import ABC, abstractmethod
import traceback

from ..util.socketutil import SocketUtil

from ..exception.atexception import AtException, AtSecondaryConnectException, AtOutboundConnectionLimitException
from .response import Response


class AtConnection(ABC):
    """
    Abstract base class for connecting to and communicating with an atprotocol server.
    """

    def __init__(self, host:str, port:int, context:ssl.SSLContext, verbose:bool=False):
        """
        Initialize the AtConnection object.

        Parameters:
        - host (str): The host name or IP address of the server.
        - port (int): The port number of the server.
        - context (ssl.SSLContext): The SSL context for secure connections.
        - verbose (bool, optional): Indicates if verbose output is enabled (default is False).
        """
        self._host = host
        self._port = port
        self._context = context
        self._addr_info = socket.getaddrinfo(host, port)[0][-1]
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._secure_root_socket = None
        self._verbose = verbose
        self._connected = False
        self.monitor_connection = None

    def __str__(self):
        """
        Return a string representation of the AtConnection object.

        Returns:
        - str: A string representation of the AtConnection object in the format "host:port".
        """
        return f"{self._host}:{self._port}"

    def write(self, data: str):
        """
        Write data to the socket.

        Parameters:
        - data (str): The data to be written to the socket.
        """
        self._secure_root_socket.write(data.encode())

    def read(self):
        """
        Read data from the socket.

        Returns:
        - str: The data read from the socket.
        """
        response = b''
        while True:
            chunk = self._secure_root_socket.read()  # Receive data in chunks of 1024 bytes
            response += chunk
            if chunk == b'@' or b'\n' in chunk:
                break
        return response.decode()

    def is_connected(self):
        """
        Check if the connection is established.

        Returns:
        - bool: True if the connection is established, False otherwise.
        """
        return self._connected

    def connect(self):
        """
        Establish a connection to the server. Throws IOException
        """
        if not self._connected:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(None) 
            self._socket.connect(self._addr_info)
            self._secure_root_socket = self._context.wrap_socket(
                self._socket, server_hostname=self._host, do_handshake_on_connect=True
            )
            
            self._stream_reader = SocketUtil(self._secure_root_socket)
            
            self._connected = True
            self.read()

    def disconnect(self):
        """
        Close the socket connection.
        """
        self._secure_root_socket.close()
        self._connected = False

    @abstractmethod
    def parse_raw_response(self, raw_response:str) -> Response:
        """
        Parse the raw response from the server.

        Parameters:
        - raw_response (str): The raw response received from the server.
        """
        pass

    def execute_command(self, command:str, raise_exception=True, retry_on_exception:int=0, read_the_response:bool=True) -> Response:
        """
        Execute a command and retrieve the response from the server.

        Parameters:
        - command (str): The command to be executed.
        - retry_on_exception (int, optional): The number of times to retry the command if an exception occurs (default is 0).
        - read_the_response (bool, optional): Indicates if the response should be read from the server (default is True).

        Returns:
        - str: The response from the server.
        """
        try:
            if not command.endswith("\n"):
                command += "\n"
            self.write(command)

            if self._verbose:
                print(f"\tSENT: {repr(command.strip())}")

            if read_the_response:
                raw_response = self.read()
                if self._verbose:
                    print(f"\tRCVD: {repr(raw_response)}")

                response = self.parse_raw_response(raw_response)
                if response.is_error():
                    if raise_exception: raise response.get_exception()
                    
                return response
            else:
                return ""
        except AtSecondaryConnectException as first:
            if retry_on_exception:
                print(f"\tCaught exception {str(first)}: reconnecting")
                try:
                    self.connect()
                    return self.execute_command(command, False)
                except Exception as second:
                    import traceback
                    traceback.print_exc()
                    raise AtOutboundConnectionLimitException(f"Failed to reconnect after original exception {str(first)}: ", second)
            else:
                self._connected = False
                raise AtSecondaryConnectException(str(first))
