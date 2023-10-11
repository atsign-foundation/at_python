class AtException(Exception):
    """
    Custom exception class for AtConnection.
    """

    def __init__(self, message):
        """
        Initialize the AtException object.

        Parameters:
        - message (str): The error message associated with the exception.
        """
        super().__init__(message)


class AtServerRuntimeException(AtException):
    """
    Custom exception class for AT0001.
    """
    def __init__(self, message):
        super().__init__(message)

class AtInvalidSyntaxException(AtException):
    """
    Custom exception class for AT0003.
    """
    def __init__(self, message):
        super().__init__(message)

class AtBufferOverFlowException(AtException):
    """
    Custom exception class for AT0005.
    """
    def __init__(self, message):
        super().__init__(message)
 
class AtOutboundConnectionLimitException(AtException):
    """
    Custom exception class for AT0006.
    """
    def __init__(self, message):
        super().__init__(message)

class AtSecondaryNotFoundException(AtException):
    """
    Custom exception class for AT0007.
    """
    def __init__(self, message):
        super().__init__(message)

class AtHandShakeException(AtException):
    """
    Custom exception class for AT0008.
    """
    def __init__(self, message):
        super().__init__(message)

class AtUnauthorizedException(AtException):
    """
    Custom exception class for AT0009.
    """
    def __init__(self, message):
        super().__init__(message)

class AtInternalServerError(AtException):
    """
    Custom exception class for AT0010.
    """
    def __init__(self, message):
        super().__init__(message)

class AtInternalServerException(AtException):
    """
    Custom exception class for AT0011.
    """
    def __init__(self, message):
        super().__init__(message)

class AtInboundConnectionLimitException(AtException):
    """
    Custom exception class for AT0012.
    """
    def __init__(self, message):
        super().__init__(message)

class AtBlockedConnectionException(AtException):
    """
    Custom exception class for AT0013.
    """
    def __init__(self, message):
        super().__init__(message)

class AtKeyNotFoundException(AtException):
    """
    Custom exception class for AT0015.
    """
    def __init__(self, message):
        super().__init__(message)

class AtInvalidAtKeyException(AtException):
    """
    Custom exception class for AT0016.
    """
    def __init__(self, message):
        super().__init__(message)

class AtSecondaryConnectException(AtException):
    """
    Custom exception class for AT0021.
    """
    def __init__(self, message):
        super().__init__(message)

class AtIllegalArgumentException(AtException):
    """
    Custom exception class for AT0022.
    """
    def __init__(self, message):
        super().__init__(message)

class AtTimeoutException(AtException):
    """
    Custom exception class for AT0023.
    """
    def __init__(self, message):
        super().__init__(message)

class AtServerIsPausedException(AtException):
    """
    Custom exception class for AT0024.
    """
    def __init__(self, message):
        super().__init__(message)

class AtUnauthenticatedException(AtException):
    """
    Custom exception class for AT0401.
    """
    def __init__(self, message):
        super().__init__(message)

class AtNewErrorCodeException(AtException):
    """
    Custom exception class for Unknown Error.
    """
    def __init__(self, message):
        super().__init__(message)

class AtResponseHandlingException(AtException):
    def __init__(self, message):
        super().__init__(message)

class AtEncryptionException(AtException):
    def __init__(self, message):
        super().__init__(message)

class AtDecryptionException(AtException):
    def __init__(self, message):
        super().__init__(message)

class AtRegistrarException(AtException):
    def __init__(self, message):
        super().__init__(message)

class AtMissingIVException(AtException):
    def __init__(self, message):
        super().__init__(message)