import unittest

from at_client.common import AtSign
from at_client.connections.atmonitorconnection import AtMonitorConnection


class MonitorSharedKeyDetectionTest(unittest.TestCase):
    """Network-free test for shared-key notification classification.

    Regression for the missing () in `str(self.atsign.to_string)`, which made the
    check compare against a bound-method repr and never match, so shared-key
    notifications were mis-typed as ordinary UPDATE notifications.
    """

    def test_detects_incoming_shared_key_notification(self):
        me = AtSign("@alice")
        key = "@alice:shared_key@bob"  # bob sharing his key with me (alice)
        self.assertTrue(AtMonitorConnection._is_shared_key_notification(me, key))

    def test_ignores_regular_update_notification(self):
        me = AtSign("@alice")
        key = "@alice:live_traffic.demo@bob"
        self.assertFalse(AtMonitorConnection._is_shared_key_notification(me, key))


if __name__ == "__main__":
    unittest.main()
