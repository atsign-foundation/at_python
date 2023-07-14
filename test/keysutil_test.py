import os, unittest, random, string
from collections import OrderedDict

from at_client.util import KeysUtil
from at_client.util import OnboardingUtil

class KeysUtilTest(unittest.TestCase):
    def test_load_keys(self):
        """Test atKeys Loading"""
        atsign = "@testAtsign1"
        keys = OrderedDict()
        onboarding_util = OnboardingUtil()
        onboarding_util.generate_encryption_keypair(keys)
        onboarding_util.generate_pkam_keypair(keys)
        onboarding_util.generate_self_encryption_key(keys)
        KeysUtil.save_keys(atsign, keys)

        loaded_keys = KeysUtil.load_keys(atsign)

        self.assertEqual(keys, loaded_keys)

    def test_save_keys_file(self):
        atsign = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

        expected = KeysUtil.get_keys_file(atsign, KeysUtil.expected_keys_files_location)
        self.assertFalse(os.path.exists(expected))

        keys = OrderedDict()
        onboarding_util = OnboardingUtil()
        onboarding_util.generate_encryption_keypair(keys)
        onboarding_util.generate_pkam_keypair(keys)
        onboarding_util.generate_self_encryption_key(keys)

        KeysUtil.save_keys(atsign, keys)

        self.assertTrue(os.path.exists(expected))


    
    
    
if __name__ == '__main__':
    unittest.main()
    