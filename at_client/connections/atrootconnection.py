import ssl
from ..common import AtSign
from ..exception.atexception import *
from .atconnection import AtConnection
from .response import Response
from .address import Address


class AtRootConnection(AtConnection):
    """
    Subclass of AtConnection representing a connection to the root server in the atprotocol.
    """

    __instance = None

    @staticmethod
    def get_instance(host:str='root.atsign.org', port:int=64, context:ssl.SSLContext=ssl.create_default_context(), verbose:bool=False):
        """
        Get an instance of AtRootConnection using the singleton pattern.

        Parameters
        ----------
        host : str, optional
            The host name or IP address of the root server (default is 'root.atsign.org').
        port : int, optional
            The port number of the root server (default is 64).
        context : ssl.SSLContext, optional
            The SSL context for secure connections (default is ssl.create_default_context()).
        verbose : bool, optional
            Indicates if verbose output is enabled (default is False).

        Returns
        -------
        AtRootConnection
            An instance of AtRootConnection.
        """
        if AtRootConnection.__instance is None:
            AtRootConnection(host, port, context, verbose)
        return AtRootConnection.__instance

    def __init__(self, host:str, port:int, context:ssl.SSLContext, verbose:bool):
        """
        Initialize the AtRootConnection object.

        Parameters
        ----------
        host : str
            The host name or IP address of the root server.
        port : int
            The port number of the root server.
        context : ssl.SSLContext
            The SSL context for secure connections.
        verbose : bool
            Indicates if verbose output is enabled.
        """
        if AtRootConnection.__instance is not None:
            raise Exception("Singleton class - use AtRootConnection.get_instance() instead")
        else:
            AtRootConnection.__instance = self
            super().__init__(host, port, context, verbose)

    def connect(self):
        """
        Establish a connection to the root server.
        """
        super().connect()
        if self._verbose:
            print("Root Connection Successful")

    def parse_raw_response(self, raw_response:str):
        """
        Parse the raw response from the root server.

        Parameters
        ----------
        raw_response : str
            The raw response received from the root server.

        Returns
        -------
        str
            The parsed response from the root server.
        """
        # Responses from root are either 'null' or <host:port>
        if raw_response.endswith("@"):
            raw_response = raw_response[:-1]

        return Response().set_raw_data_response(raw_response.strip())

    def find_secondary(self, atsign:AtSign):
        """
        Find the secondary server for the given atsign on the root server.

        Parameters
        ----------
        atsign : str
            The atsign to lookup.

        Returns
        -------
        str
            The secondary server for the given atsign.

        Raises
        ------
        AtException
            If the root lookup returns null or a malformed response is received.
        """
        if not self.is_connected():
            try:
                self.connect()
            except Exception as e:
                # Connect will only throw an Exception if authentication fails. Root connections do not require authentication.
                raise AtException(f"Root Connection failed - {e}")

        response = self.execute_command(atsign.without_prefix, False).get_raw_data_response()

        if response == "null":
            raise AtSecondaryNotFoundException(f"Root lookup returned null for {atsign}")
        else:
            try:
                return Address.from_string(response)
            except ValueError as e:
                raise AtException(f"Received malformed response {response} from lookup of {atsign} on root server")
