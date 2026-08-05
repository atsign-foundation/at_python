import ssl
from .atconnection import AtConnection
from .address import Address
from .response import Response


class AtSecondaryConnection(AtConnection):
    """
    Subclass of AtConnection representing a connection to the secondary server in the atprotocol.
    """

    def __init__(self, address: Address, context:ssl.SSLContext=None, verbose:bool=False):
        """
        Initialize the AtSecondaryConnection object.

        Parameters
        ----------
        host : str
            The host name or IP address of the secondary server.
        port : int
            The port number of the secondary server.
        context : ssl.SSLContext, optional
            The SSL context for secure connections (default is None).
        verbose : bool, optional
            Indicates if verbose output is enabled (default is False).
        """
        super().__init__(address.host, address.port, context, verbose)

    def connect(self):
        """
        Establish a connection to the secondary server.
        """
        super().connect()
        if self._verbose:
            print("Secondary Connection Successful")

    def parse_raw_response(self, raw_response:str):
        """
        Parse the raw response from the secondary server.

        Parameters
        ----------
        raw_response : str
            The raw response received from the secondary server.

        Returns
        -------
        str
            The parsed response from the secondary server.
        """
        if raw_response.endswith("@"):
            raw_response = raw_response[:-1]
        raw_response = raw_response.strip()

        data_index = raw_response.find("data:")
    
        error_index = raw_response.find("error:")
        notification_index = raw_response.find("notification")
        if data_index > -1:
            return Response().set_raw_data_response(raw_response[data_index+len("data:"):].split("\n")[0])
        elif error_index > -1:
            return Response().set_raw_error_response(raw_response[error_index+len("error:"):])
        elif notification_index > -1:
            return Response().set_raw_data_response(raw_response[notification_index+len("notification"):])
        else:
            raise ValueError(f"Invalid response from server: {raw_response}")
