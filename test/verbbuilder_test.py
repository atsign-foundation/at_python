import re
import unittest
from at_client.util.verbbuilder import *
from at_client.common import AtSign
from at_client.common.keys import SharedKey, PublicKey, PrivateHiddenKey, SelfKey

class AtVerbBuilderTest(unittest.TestCase):
    verbose = False

    def test_from_verb_builder(self):
        """
        Test From Verb Builder.
        """
        command = FromVerbBuilder().set_shared_by("@bob").build()
        self.assertEqual(command, "from:@bob")

    def test_pkam_verb_builder(self):
        """
        Test PKAM Verb Builder.
        """
        command = PKAMVerbBuilder().set_digest("digest").build()
        self.assertEqual(command, "pkam:digest")
    
    def test_scan_verb_builder(self):
        """
        Test Scan Verb Builder.
        """
        # Test not setting any parameters
        command = ScanVerbBuilder().build()
        self.assertEqual(command, "scan")

        # Test setting just regex
        command = ScanVerbBuilder().set_regex("*.public").build()
        self.assertEqual(command, "scan *.public")

        # Test setting just fromAtSign
        command = ScanVerbBuilder().set_from_at_sign("@other").build()
        self.assertEqual(command, "scan:@other")

        # Test setting just showHidden
        command = ScanVerbBuilder().set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true")

        # Test setting regex & fromAtSign
        command = ScanVerbBuilder().set_regex("*.public").set_from_at_sign("@other").build()
        self.assertEqual(command, "scan:@other *.public")

        # Test setting regex & showHidden
        command = ScanVerbBuilder().set_regex("*.public").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true *.public")

        # Test setting fromAtSign & showHidden
        command = ScanVerbBuilder().set_from_at_sign("@other").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true:@other")

        # Test setting regex & fromAtSign & showHidden
        command = ScanVerbBuilder().set_regex("*.public").set_from_at_sign("@other").set_show_hidden(True).build()
        self.assertEqual(command, "scan:showHidden:true:@other *.public")

    def test_update_verb_builder(self):
        """
        Test Update Verb Builder.
        """
         
        builder = UpdateVerbBuilder()
        command = builder.set_key_name("test").set_shared_by("@bob").set_value("my Value 123").build()
        self.assertEqual("update:test@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("test").set_shared_by("@bob").set_shared_with("@bob").set_value("My value 123").build()
        self.assertEqual("update:@bob:test@bob My value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("publickey").set_shared_by("@bob").set_is_public(True).set_value("my Value 123").build()
        self.assertEqual("update:public:publickey@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("publickey").set_shared_by("@alice").set_is_public(True).set_is_cached(True).set_value("my Value 123").build()
        self.assertEqual("update:cached:public:publickey@alice my Value 123", command)

        builder = UpdateVerbBuilder()
        command = builder.set_key_name("sharedkey").set_shared_by("@bob").set_shared_with("@alice").set_value("my Value 123").build()
        self.assertEqual("update:@alice:sharedkey@bob my Value 123", command)

        builder = UpdateVerbBuilder()
        sk1 = SharedKey("test", AtSign("@bob"), AtSign("@alice"))
        sk1.metadata.is_binary = True
        sk1.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk1, "myBinaryValue123456").build()
        self.assertEqual(
            "update:ttl:600000:isBinary:true:isEncrypted:true:@alice:test@bob myBinaryValue123456", command
        )

        builder = UpdateVerbBuilder()
        pk1 = PublicKey("test", AtSign("@bob"))
        pk1.metadata.is_cached = True
        command = builder.with_at_key(pk1, "myValue123").build()
        self.assertEqual("update:cached:public:test@bob myValue123", command)

        builder = UpdateVerbBuilder()
        sk2 = SelfKey("test", AtSign("@bob"))
        sk2.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk2, "myValue123").build()
        self.assertEqual("update:ttl:600000:isEncrypted:true:test@bob myValue123", command)

        builder = UpdateVerbBuilder()
        bob = AtSign("@bob")
        sk3 = SelfKey("test", bob, bob)
        sk3.metadata.ttl = 1000 * 60 * 10  # 10 minutes
        command = builder.with_at_key(sk3, "myValue123").build()
        self.assertEqual("update:ttl:600000:isEncrypted:true:@bob:test@bob myValue123", command)

    def test_llookup_verb_builder(self):
        """
        Test Llookup Verb Builder.
        """
        builder = LlookupVerbBuilder()
        command = ""
        alice = "@alice"
        bob = "@bob"

        # Type.NONE self key
        command = builder.set_key_name("test").set_shared_by(alice).build() 
        self.assertEqual("llookup:test@alice", command)

        # Type.METADATA self key
        command = builder.set_type(LlookupVerbBuilder.Type.METADATA).build()
        self.assertEqual("llookup:meta:test@alice", command)

        # hidden self key, meta
        command = builder.set_is_hidden(True).build() 
        self.assertEqual("llookup:meta:_test@alice", command)

        # Type.ALL public cached key
        builder = LlookupVerbBuilder().set_shared_by(alice)
        builder.set_key_name("publickey").set_is_cached(True).set_is_public(True)
        command = builder.set_type(LlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("llookup:all:cached:public:publickey@alice", command)

        # no key name
        with self.assertRaises(ValueError):
            builder = LlookupVerbBuilder()
            builder.set_shared_by(alice).build()

        # no shared by
        with self.assertRaises(ValueError):
            builder = LlookupVerbBuilder()
            builder.set_key_name("test").build()

        # no key name and no shared by
        with self.assertRaises(ValueError):
            builder = LlookupVerbBuilder().build()

        # with public key
        builder = LlookupVerbBuilder()
        pk = PublicKey("publickey", bob)
        command = builder.with_at_key(pk, LlookupVerbBuilder.Type.METADATA).build()
        self.assertEqual("llookup:meta:public:publickey@bob", command)

        # with shared key
        builder = LlookupVerbBuilder()
        sk = SharedKey("sharedkey", bob, alice)
        command = builder.with_at_key(sk, LlookupVerbBuilder.Type.NONE).build()
        self.assertEqual("llookup:@alice:sharedkey@bob", command)

        # with self key
        builder = LlookupVerbBuilder()
        sfk1 = SelfKey("test", bob)
        command = builder.with_at_key(sfk1, LlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("llookup:all:test@bob", command)

        # with self key (shared with self)
        builder = LlookupVerbBuilder()
        sfk2 = SelfKey("test", bob, bob)
        command = builder.with_at_key(sfk2, LlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("llookup:all:@bob:test@bob", command)

        # with cached public key
        builder = LlookupVerbBuilder()
        pk2 = PublicKey("publickey", bob)
        pk2.metadata.is_cached = True
        command = builder.with_at_key(pk2, LlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("llookup:all:cached:public:publickey@bob", command)

        # with cached shared key
        builder = LlookupVerbBuilder()
        sk2 = SharedKey("sharedkey", bob, alice)
        sk2.metadata.is_cached = True
        command = builder.with_at_key(sk2, LlookupVerbBuilder.Type.NONE).build()
        self.assertEqual("llookup:cached:@alice:sharedkey@bob", command)

    def test_lookup_verb_builder(self):
        """
        Test Lookup Verb Builder.
        """
        builder = LookupVerbBuilder()

        # Type.NONE
        command = builder.set_key_name("test").set_shared_with("@alice").build() 
        self.assertEqual("lookup:test@alice", command)

        # Type.METADATA
        command = builder.set_type(LookupVerbBuilder.Type.METADATA).build()
        self.assertEqual("lookup:meta:test@alice", command)

        # Type.ALL
        command = builder.set_type(LookupVerbBuilder.Type.ALL).build() 
        self.assertEqual("lookup:all:test@alice", command)

        # no key name
        with self.assertRaises(ValueError):
            builder = LookupVerbBuilder().set_shared_with("@alice").build()

        # no shared with
        with self.assertRaises(ValueError):
            builder = LookupVerbBuilder().set_key_name("test").build()

        # no key name and no shared with
        with self.assertRaises(ValueError):
            builder = LookupVerbBuilder().build()

        # with shared key
        builder = LookupVerbBuilder()
        sk = SharedKey("test", AtSign("@sharedby"), AtSign("@sharedwith"))
        command = builder.with_shared_key(sk, LookupVerbBuilder.Type.METADATA).build()
        self.assertEqual("lookup:meta:test@sharedwith", command)

    def test_plookup_verb_builder(self):
        """
        Test Plookup Verb Builder.
        """
        builder = PlookupVerbBuilder()

        # Type.NONE
        command = builder.set_key_name("publickey").set_shared_by("alice").build()
        self.assertEqual("plookup:publickey@alice", command)

        # Type.METADATA
        command = builder.set_type(PlookupVerbBuilder.Type.METADATA).build()
        self.assertEqual("plookup:meta:publickey@alice", command)

        # Type.ALL
        command = builder.set_type(PlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("plookup:all:publickey@alice", command)

        # no key
        with self.assertRaises(ValueError):
            builder = PlookupVerbBuilder()
            builder.set_shared_by("@alice").set_type(PlookupVerbBuilder.Type.ALL).build()

        # no shared by
        with self.assertRaises(ValueError):
            builder = PlookupVerbBuilder().set_key_name("publickey").set_type(PlookupVerbBuilder.Type.ALL).build()

        # no key and no shared by
        with self.assertRaises(ValueError):
            builder = PlookupVerbBuilder().set_type(PlookupVerbBuilder.Type.ALL).build()

        # with
        builder = PlookupVerbBuilder()
        pk = PublicKey("publickey", AtSign("@bob"))
        command = builder.with_at_key(pk, PlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("plookup:all:publickey@bob", command)

        # bypasscache true
        builder = PlookupVerbBuilder()
        builder.set_key_name("publickey").set_shared_by("alice").set_bypass_cache(True)
        command = builder.set_type(PlookupVerbBuilder.Type.ALL).build()
        self.assertEqual("plookup:bypassCache:true:all:publickey@alice", command)

    def test_delete_verb_builder(self):
        """
        Test Delete Verb Builder.
        """
        builder = DeleteVerbBuilder()

        # delete a public key
        command = builder.set_is_public(True).set_key_name("publickey").set_shared_by("@alice").build()
        self.assertEqual("delete:public:publickey@alice", command)

        # delete a cached public key
        builder = DeleteVerbBuilder().set_is_cached(True).set_is_public(True)
        command = builder.set_key_name("publickey").set_shared_by("@bob").build()
        self.assertEqual("delete:cached:public:publickey@bob", command)

        # delete a self key
        command = DeleteVerbBuilder().set_key_name("test").set_shared_by("@alice").build()
        self.assertEqual("delete:test@alice", command)

        # delete a hidden self key
        command = DeleteVerbBuilder().set_is_hidden(True).set_key_name("test").set_shared_by("@alice").build()
        self.assertEqual("delete:_test@alice", command)

        # delete a shared key
        command = DeleteVerbBuilder().set_key_name("test").set_shared_by("@alice").set_shared_with("@bob").build()
        self.assertEqual("delete:@bob:test@alice", command)

        # delete a cached shared key
        builder = DeleteVerbBuilder().set_is_cached(True).set_key_name("test")
        command = builder.set_shared_by("@alice").set_shared_with("@bob").build()
        self.assertEqual("delete:cached:@bob:test@alice", command)

        # missing key name
        with self.assertRaises(ValueError):
            DeleteVerbBuilder().set_shared_by("@alice").set_shared_with("@bob").build()

        # missing shared by
        with self.assertRaises(ValueError):
            builder = DeleteVerbBuilder().set_key_name("test").build()

        # missing key name and shared by
        with self.assertRaises(ValueError):
            builder = DeleteVerbBuilder().build()

        # with self key
        self_key = SelfKey("test", AtSign("@alice"))
        command = DeleteVerbBuilder().with_at_key(self_key).build()
        self.assertEqual("delete:test@alice", command)

        # with public key
        pk = PublicKey("publickey", AtSign("@bob"))
        command = DeleteVerbBuilder().with_at_key(pk).build()
        self.assertEqual("delete:public:publickey@bob", command)

        # with shared key
        sk = SharedKey("test", AtSign("@alice"), AtSign("@bob"))
        command = DeleteVerbBuilder().with_at_key(sk).build()
        self.assertEqual("delete:@bob:test@alice", command)


    def test_notify_verb_builder(self):
        # with a shared key, no metadata and no namespace
        sk = SharedKey("test", AtSign("@alice"), AtSign("@bob"))
        command = NotifyVerbBuilder().with_at_key(sk).build()
        command_without_id = re.sub(r'\bid:[^:]*:', '', command)
        self.assertRegex("notify:ttr:-1:@bob:test@alice", command_without_id)
        
        #with a shared key, metadata and no namespace
        sk = SharedKey("test", AtSign("@alice"), AtSign("@bob"))
        metadata = Metadata(ttl="1000", ttr="-1")
        sk.metadata = metadata
        command = NotifyVerbBuilder().with_at_key(sk).build()
        command_without_id = re.sub(r'\bid:[^:]*:', '', command)
        self.assertRegex("notify:ttl:1000ttr:-1:@bob:test@alice", command_without_id)
        
        #with a shared key, no metadata and namespace
        sk = SharedKey("test", AtSign("@alice"), AtSign("@bob"))
        sk.namespace = "dave"
        command = NotifyVerbBuilder().with_at_key(sk).build()
        command_without_id = re.sub(r'\bid:[^:]*:', '', command)
        self.assertRegex("notify:ttr:-1:@bob:test.dave@alice", command_without_id)
        
        #with a shared key, metadata and namespace
        sk = SharedKey("test", AtSign("@alice"), AtSign("@bob"))
        metadata = Metadata(ttl="1000", ttr="-1")
        sk.metadata = metadata
        sk.namespace = "dave"
        command = NotifyVerbBuilder().with_at_key(sk).build()
        command_without_id = re.sub(r'\bid:[^:]*:', '', command)
        self.assertRegex("notify:ttl:1000:ttr:-1:@bob:test.dave@alice", command_without_id)
        
if __name__ == '__main__':
    unittest.main()
