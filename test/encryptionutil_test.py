import unittest, base64

from at_client.util import EncryptionUtil

class EncryptionUtilTest(unittest.TestCase):

    def test_aes_encryption(self):
        """Test generating an AES key and encryption/decryption."""
        secret_key = EncryptionUtil.generate_aes_key_base64()
        plain_text = "AES"
        iv_nonce = EncryptionUtil.generate_iv_nonce()
        encrypted_text = EncryptionUtil.aes_encrypt_from_base64(plain_text, secret_key, iv_nonce)
        decrypted_text = EncryptionUtil.aes_decrypt_from_base64(encrypted_text, secret_key, iv_nonce)
        self.assertEqual(plain_text, decrypted_text)
    
    def test_rsa_encryption(self):
        """Test generating RSA key pair and encryption/decryption."""
        private_key, public_key = EncryptionUtil.generate_rsa_key_pair()
        plain_text = "RSA"
        encrypted_text = EncryptionUtil.rsa_encrypt_to_base64(plain_text, base64.b64encode(public_key).decode("utf-8"))
        decrypted_text = EncryptionUtil.rsa_decrypt_from_base64(encrypted_text, base64.b64encode(private_key).decode("utf-8"))
        self.assertEqual(plain_text, decrypted_text)

if __name__ == '__main__':
    unittest.main()
    