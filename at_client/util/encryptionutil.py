import base64
import binascii
import os
import random
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
from cryptography.hazmat.primitives import hashes


class EncryptionUtil:
    @staticmethod
    def aes_encrypt_from_base64(clear_text, key_base64, iv=b'\x00' * 16):
        clear_text = clear_text.encode('utf-8')
        key = base64.b64decode(key_base64)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(clear_text) + padder.finalize()
        cipher_text = encryptor.update(padded_plaintext) + encryptor.finalize()
        return base64.b64encode(cipher_text).decode()

    @staticmethod
    def aes_decrypt_from_base64(encrypted_text, self_encryption_key, iv=b'\x00' * 16):
        cipher_text = base64.b64decode(encrypted_text)
        key = base64.b64decode(self_encryption_key)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        # Unpad the plain_text using PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plain_text = padder.update(plain_text) + padder.finalize()

        # Print the decrypted plaintext
        return plain_text.decode('utf-8')

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption())
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return private_key_bytes, public_key_bytes

    @staticmethod
    def generate_aes_key_base64():
        return base64.b64encode(os.urandom(32)).decode("utf-8")

    @staticmethod
    def rsa_decrypt_from_base64(cipher_text, private_key_bytes):
        private_key = EncryptionUtil.private_key_from_base64(private_key_bytes)
        decrypted_bytes = private_key.decrypt(
            base64.b64decode(cipher_text),
            rsa_padding.PKCS1v15()
        )
        return decrypted_bytes.decode('utf-8')

    @staticmethod
    def rsa_encrypt_to_base64(clear_text, public_key_bytes):
        public_key = EncryptionUtil.public_key_from_base64(public_key_bytes)
        encrypted_bytes = public_key.encrypt(
            clear_text.encode('utf-8'),
            rsa_padding.PKCS1v15()
        )
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    @staticmethod
    def sign_sha256_rsa(input_data, private_key_bytes):
        private_key = EncryptionUtil.private_key_from_base64(private_key_bytes)
        signature = private_key.sign(
            input_data.encode('utf-8'),
            rsa_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def private_key_from_base64(s):
        key_bytes = base64.b64decode(s.encode('utf-8'))
        return load_der_private_key(key_bytes, password=None)
    
    @staticmethod
    def public_key_from_base64(s):
        key_bytes = base64.b64decode(s.encode('utf-8'))
        return load_der_public_key(key_bytes)
    
    @staticmethod
    def generate_iv_nonce():
        return secrets.token_bytes(16)
        