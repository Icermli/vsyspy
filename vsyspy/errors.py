class VSYSPYException(Exception):
    pass


class InvalidParameterException(VSYSPYException):
    pass


class InvalidAddressException(VSYSPYException):
    pass


class NetworkException(VSYSPYException):
    pass


class MissingPrivateKeyException(VSYSPYException):
    pass


class MissingPublicKeyException(VSYSPYException):
    pass


class InsufficientBalanceException(VSYSPYException):
    pass


class InvalidStatus(VSYSPYException):
    pass


class MissingAddressException(VSYSPYException):
    pass
