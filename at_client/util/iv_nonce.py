import base64
from at_client.util.encryptionutil import EncryptionUtil


class IVNonce:
    def __init__(self, iv_nonce_bytes=EncryptionUtil.generate_iv_nonce()):
        self.iv_nonce_bytes = iv_nonce_bytes

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.as_b64()
    
    def as_b64(self):
        b64_str = ""
        if self.iv_nonce_bytes:
            b64_str = base64.b64encode(self.iv_nonce_bytes).rstrip().decode('utf-8')
        return b64_str
    
    def as_bytes(self):
        return self.iv_nonce_bytes
    
    @classmethod
    def from_b64(cls, b64_str: str):
        return cls(base64.b64decode(b64_str))
    
    def set_iv_nonce_bytes(self, iv_nonce_bytes):
        self.iv_nonce_bytes = iv_nonce_bytes
        return self
    
    @staticmethod
    def get_bytes_from_b64(b64_str: str):
        return base64.b64decode(b64_str)