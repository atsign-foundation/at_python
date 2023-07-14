from .atsign import AtSign
from .metadata import Metadata
from ..exception import AtException
from ..util.keystringutil import KeyStringUtil, KeyType

class Keys:
    @staticmethod
    def from_string(full_at_key_name: str):
        key_string_util = KeyStringUtil(full_at_key_name)
        key_type = key_string_util.get_key_type()
        key_name = key_string_util.get_key_name()
        shared_by = AtSign(key_string_util.get_shared_by())
        shared_with = AtSign(key_string_util.get_shared_with()) if key_string_util.get_shared_with() else None
        namespace = key_string_util.get_namespace()
        is_cached = key_string_util.is_cached()
        is_hidden = key_string_util.is_hidden()

        at_key = None
        if key_type == KeyType.PUBLIC_KEY:
            at_key = PublicKey(key_name, shared_by)
        elif key_type == KeyType.SHARED_KEY:
            at_key = SharedKey(key_name, shared_by, shared_with)
        elif key_type == KeyType.SELF_KEY:
            at_key = SelfKey(key_name, shared_by, shared_with)
        elif key_type == KeyType.PRIVATE_HIDDEN_KEY:
            at_key = PrivateHiddenKey(key_name, shared_by)
        else:
            raise AtException(f"Could not find KeyType for Key {full_at_key_name}")

        at_key.set_namespace(namespace)
        at_key.metadata.is_cached = is_cached
        if not at_key.metadata.is_hidden:
            at_key.metadata.is_hidden = is_hidden  # If KeyBuilders constructor did not already evaluate is_hidden, then do it here

        return at_key



class AtKey:
    def __init__(self, name, shared_by):
        self.name = name
        self.shared_with = None
        self.shared_by = shared_by
        self.namespace = None
        self.metadata = Metadata()

    def __repr__(self):
        return str(self)

    def __str__(self):
        s = ""
        if self.metadata.is_public:
            s += "public:"
        elif self.shared_with:
            s += str(self.shared_with) + ":"
        s += self.get_fully_qualified_key_name()
        if self.shared_by:
            s += str(self.shared_by)
        return s

    def get_namespace(self):
        return self.namespace

    def set_namespace(self, namespace):
        if namespace:
            while namespace.startswith("."):
                namespace = namespace[1:]
            namespace = namespace.strip()
        self.namespace = namespace
        return self

    def get_fully_qualified_key_name(self):
        return self.name + (f".{self.namespace}" if self.namespace else "")
    
    def set_name(self, name):
        self.name = name.strip()
        return self

    def set_time_to_live(self, ttl: int):
        self.metadata.ttl = ttl
        return self

    def set_time_to_birth(self, ttb: int):
        self.metadata.ttb = ttb
        return self


class PublicKey(AtKey):
    def __init__(self, name, shared_by: AtSign):
        super().__init__(name, shared_by=shared_by)
        self.metadata.is_public = True
        self.metadata.is_encrypted = False
        self.metadata.is_hidden = False

    def cache(self, ttr, ccd):
        self.metadata.ttr = ttr
        self.metadata.ccd = ccd
        self.metadata.is_cached = (ttr != 0)
        return self


class SelfKey(AtKey):
    def __init__(self, name, shared_by: AtSign, shared_with: AtSign = None):
        super().__init__(name, shared_by=shared_by)
        self.shared_with = shared_with
        self.metadata.is_public = False
        self.metadata.is_encrypted = True
        self.metadata.is_hidden = False


class SharedKey(AtKey):
    def __init__(self, name, shared_by: AtSign, shared_with: AtSign):
        super().__init__(name, shared_by=shared_by)
        if not shared_with:
            raise AtException("SharedKey: shared_with may not be null")
        self.shared_with = shared_with
        self.metadata.is_public = False
        self.metadata.is_encrypted = True
        self.metadata.is_hidden = False

    def cache(self, ttr, ccd):
        self.metadata.ttr = ttr
        self.metadata.ccd = ccd
        self.metadata.is_cached = (ttr != 0)
        return self

    @staticmethod
    def from_string(key: str) -> 'SharedKey':
        if not key:
            raise AtException("SharedKey.from_string(key): key may not be null")
        split_by_colon = key.split(":")
        if len(split_by_colon) != 2:
            raise AtException("SharedKey.from_string('" + key + "'): key must have structure @bob:foo.bar@alice")
        shared_with = split_by_colon[0]
        split_by_at_sign = split_by_colon[1].split("@")
        if len(split_by_at_sign) != 2:
            raise AtException("SharedKey.from_string('" + key + "'): key must have structure @bob:foo.bar@alice")
        key_name = split_by_at_sign[0]
        shared_by = split_by_at_sign[1]
        shared_key = SharedKey(key_name, AtSign(shared_by), AtSign(shared_with))
        shared_key.name = key_name
        return shared_key
    
    def get_shared_shared_key_name(self):
        return f"{self.shared_with}:shared_key{self.shared_by}"



class PrivateHiddenKey(AtKey):
    def __init__(self, name, shared_by: AtSign):
        super().__init__(name, shared_by=shared_by)