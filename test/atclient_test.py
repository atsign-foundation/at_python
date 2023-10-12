import unittest, random, string
from configparser import ConfigParser

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import PublicKey, SelfKey, SharedKey
from at_client.exception import *
from at_client.util.iv_nonce import IVNonce
from test_wrapper import skip_if_dependabot_pr

class AtClientTest(unittest.TestCase):
    verbose = False
    atsign1 = atsign2 = ""
    root_server = secondary_server = None

    @classmethod
    def setUpClass(cls) -> None:
        config = ConfigParser()
        config.read('config.ini')
        cls.atsign1 = config.get("test_atsigns", "atsign1", fallback="@27barracuda")
        cls.atsign2 = config.get("test_atsigns", "atsign2", fallback="@amateur93")
        return super().setUpClass()

    @skip_if_dependabot_pr
    def test_atsign_pkam_authenticate(self):
        """Test PKAM Authentication"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        self.assertTrue(atclient.is_authenticated())

    @skip_if_dependabot_pr
    def test_get_at_keys(self):
        """Test Scan Verb using get_at_keys"""

        # Test to fetch all keys
        atsign = AtSign(self.atsign2)
        atclient = AtClient(atsign, verbose=self.verbose)
        my_keys = atclient.get_at_keys("", fetch_metadata=True)
        self.assertTrue(len(my_keys)>0)

        # Test Regex functionality
        my_keys = atclient.get_at_keys("test", fetch_metadata=True)
        self.assertEqual(len(my_keys), 4)

        my_keys = atclient.get_at_keys("no_key", fetch_metadata=True)
        self.assertEqual(len(my_keys), 0)

    @skip_if_dependabot_pr
    def test_put_public_key(self):
        """Test Put Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        pk = PublicKey("test_public_key", atsign)
        response = atclient.put(pk, "test1")
        self.assertIsNotNone(response)

    @skip_if_dependabot_pr
    def test_put_self_key(self):
        """Test Put Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        iv = IVNonce().as_b64()
        sk = SelfKey("test_self_key", atsign).set_iv_nonce(iv)
        response = atclient.put(sk, "test1")
        self.assertIsNotNone(response)

    @skip_if_dependabot_pr
    def test_put_shared_key(self):
        """Test Put Function with Shared Key"""
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("test_shared_key", shared_by, shared_with).set_iv_nonce(IVNonce().as_b64())
        response = atclient.put(sk, "test1")
        self.assertIsNotNone(response)

        shared_with = AtSign(self.atsign1)
        shared_by = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        sk = SharedKey("test_shared_key2", shared_by, shared_with).set_iv_nonce(IVNonce().as_b64())
        response = atclient.put(sk, "test2")
        self.assertIsNotNone(response)

        # Invalid atsign with atclient
        with self.assertRaises(AtIllegalArgumentException):
            shared_by = AtSign(self.atsign1)
            shared_with = AtSign(self.atsign2)
            atclient = AtClient(shared_by, verbose=self.verbose)
            sk = SharedKey("test_shared_key3", shared_with, shared_by)
            response = atclient.put(sk, "test2")

    @skip_if_dependabot_pr
    def test_get_public_encryption_key(self):
        atsign1 = AtSign(self.atsign1)
        atsign2 = AtSign(self.atsign2)
        atclient = AtClient(atsign1, verbose=self.verbose)
        key = atclient.get_public_encryption_key(atsign2)
        self.assertIsNotNone(key)

        # Server not found Exception
        with self.assertRaises(AtSecondaryNotFoundException):
            unknown_atsign = AtSign("unknown")
            key = atclient.get_public_encryption_key(unknown_atsign)

        # Key not found
        _atsign = AtSign("@6armadillo")
        key = atclient.get_public_encryption_key(_atsign)
        self.assertIsNone(key)

    @skip_if_dependabot_pr
    def test_create_shared_encryption_key(self):
        atsign1 = AtSign(self.atsign1)
        atsign2 = AtSign(self.atsign2)
        atclient = AtClient(atsign1, verbose=self.verbose)
        sk = SharedKey("test_shared_key", atsign1, atsign2)
        key = atclient.create_shared_encryption_key(sk)
        self.assertIsNotNone(key)

        # Key not found Exception
        with self.assertRaises(AtKeyNotFoundException):
            armadilo_atsign = AtSign("6armadillo")
            sk = SharedKey("test_shared_key", atsign1, armadilo_atsign)
            key = atclient.create_shared_encryption_key(sk)

    @skip_if_dependabot_pr
    def test_get_encryption_key_shared_by_me(self):
        atsign1 = AtSign(self.atsign1)
        atsign2 = AtSign(self.atsign2)
        atclient = AtClient(atsign1, verbose=self.verbose)
        sk = SharedKey("test_shared_key", atsign1, atsign2)
        key = atclient.get_encryption_key_shared_by_me(sk)
        self.assertIsNotNone(key)

        # Key not found Exception
        with self.assertRaises(AtKeyNotFoundException):
            armadilo_atsign = AtSign("6armadillo")
            sk = SharedKey("test_shared_key", atsign1, armadilo_atsign)
            key = atclient.get_encryption_key_shared_by_me(sk)

    @skip_if_dependabot_pr
    def test_get_encryption_key_shared_by_other(self):
        atsign1 = AtSign(self.atsign1)
        atsign2 = AtSign(self.atsign2)
        atclient = AtClient(atsign1, verbose=self.verbose)
        sk = SharedKey("test_shared_key2", atsign2, atsign1)
        key = atclient.get_encryption_key_shared_by_other(sk)
        self.assertIsNotNone(key)

        # Key not found Exception
        with self.assertRaises(AtKeyNotFoundException):
            armadilo_atsign = AtSign("6armadillo")
            sk = SharedKey("test_shared_key", atsign1, armadilo_atsign)
            key = atclient.get_encryption_key_shared_by_other(sk)

    @skip_if_dependabot_pr
    def test_not_implemented_key_exception(self):
        atsign1 = AtSign(self.atsign1)
        atclient = AtClient(atsign1, verbose=self.verbose)
        
        with self.assertRaises(NotImplementedError):
            atclient.put(None, None)

        with self.assertRaises(NotImplementedError):
            atclient.get(None)

        with self.assertRaises(NotImplementedError):
            atclient.delete(None)

    @skip_if_dependabot_pr
    def test_get_self_key(self):
        """Test Get Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        iv = IVNonce().as_b64()
        sk = SelfKey("test_self_key", atsign).set_iv_nonce(iv)
        response = atclient.put(sk, "test1")
        response = atclient.get(sk)
        self.assertEqual("test1", response)

        # Self Key not found test
        with self.assertRaises(AtKeyNotFoundException):
            unknown = SelfKey("unknown", atsign)
            response = atclient.get(unknown)

    @skip_if_dependabot_pr
    def test_get_public_key(self):
        """Test Get Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        pk = PublicKey("test_public_key", atsign)
        response = atclient.put(pk, "test1")
        response = atclient.get(pk)
        self.assertEqual("test1", response)

        amateur_atsign = AtSign(self.atsign2)
        atclient = AtClient(amateur_atsign, verbose=self.verbose)
        response = atclient.get(pk)
        self.assertEqual("test1", response)

        # Public Key not found test
        with self.assertRaises(AtInternalServerException):
            unknown_pk = PublicKey("unknown_key", atsign)
            response = atclient.get(unknown_pk)

    @skip_if_dependabot_pr
    def test_get_shared_key(self):
        """Test Get Function with Shared Key"""
        # Shared by me with other
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        iv = IVNonce().as_b64()
        sk = SharedKey("test_shared_key1445", shared_by, shared_with).set_iv_nonce(iv)
        atclient.put(sk, "test")
        response = atclient.get(sk)
        self.assertEqual("test", response)

        # Shared by other with me
        iv = IVNonce().as_b64()
        sk = SharedKey("test_shared_key2", shared_with, shared_by)
        atclient.put(SharedKey("test_shared_key2", shared_by, shared_with).set_iv_nonce(iv), "test2")
        response = atclient.get(sk)
        self.assertEqual("test2", response)

        # Shared Key not found test
        with self.assertRaises(AtKeyNotFoundException):
            unknown = SharedKey("unknown", shared_by, shared_with)
            response = atclient.get(unknown)

    @skip_if_dependabot_pr
    def test_delete_public_key(self):
        """Test Delete Function with Public Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        random_key_name  = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        pk = PublicKey(random_key_name, atsign)
        response = atclient.put(pk, "test1")

        response = atclient.delete(pk)
        self.assertIsNotNone(response)

    @skip_if_dependabot_pr
    def test_delete_self_key(self):
        """Test Delete Function with Self Key"""
        atsign = AtSign(self.atsign1)
        atclient = AtClient(atsign, verbose=self.verbose)
        random_key_name  = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        sk = SelfKey(random_key_name, atsign).set_iv_nonce(IVNonce().as_b64())
        response = atclient.put(sk, "test1")

        response = atclient.delete(sk)
        self.assertIsNotNone(response)

    @skip_if_dependabot_pr
    def test_delete_shared_key(self):
        """Test Delete Function with Shared Key"""
        shared_by = AtSign(self.atsign1)
        shared_with = AtSign(self.atsign2)
        atclient = AtClient(shared_by, verbose=self.verbose)
        random_key_name  = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        sk = SharedKey(random_key_name, shared_by, shared_with).set_iv_nonce(IVNonce().as_b64())
        response = atclient.put(sk, "test1")

        response = atclient.delete(sk)
        self.assertIsNotNone(response)

    
    
if __name__ == '__main__':
    unittest.main()
    