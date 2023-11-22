import base64
import binascii
from enum import Enum
from abc import ABC, abstractmethod
import uuid
from ..common.atsign import AtSign
from ..common.metadata import Metadata

class VerbBuilder(ABC):
    @abstractmethod
    def build(self):
        raise NotImplementedError("Subclasses must implement the build() method")


class FromVerbBuilder(VerbBuilder):
    def __init__(self):
        self.shared_by = ""

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def build(self):
        return f"from:{self.shared_by}"

class PKAMVerbBuilder(VerbBuilder):
    def __init__(self):
        self.digest = ""

    def set_digest(self, digest):
        self.digest = digest
        return self

    def build(self):
        return f"pkam:{self.digest}"
    
class CRAMVerbBuilder(VerbBuilder):
    def __init__(self):
        self.digest = ""

    def set_digest(self, digest):
        self.digest = digest
        return self

    def build(self):
        return f"cram:{self.digest}"


class ScanVerbBuilder(VerbBuilder):
    def __init__(self):
        self.regex = None
        self.from_at_sign = None
        self.show_hidden = False

    def set_regex(self, regex):
        self.regex = regex
        return self

    def set_from_at_sign(self, from_at_sign):
        self.from_at_sign = from_at_sign
        return self

    def set_show_hidden(self, show_hidden):
        self.show_hidden = show_hidden
        return self

    def build(self):
        command = "scan"

        if self.show_hidden:
            command += ":showHidden:true"

        if self.from_at_sign and self.from_at_sign.strip() != "":
            command += ":" + self.from_at_sign

        if self.regex is not None and self.regex.strip() != "":
            command += " " + self.regex

        return command


class UpdateVerbBuilder(VerbBuilder):
    def __init__(self):
        self.key = None
        self.shared_by = None
        self.shared_with = None
        self.is_hidden = None
        self.is_public = None
        self.is_cached = False
        self.ttl = None
        self.ttb = None
        self.ttr = None
        self.ccd = None
        self.is_binary = None
        self.is_encrypted = None
        self.data_signature = None
        self.shared_key_enc = None
        self.pub_key_cs = None
        self.encoding = None
        self.value = None

    def set_key_name(self, key_name):
        self.key = key_name
        return self

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def set_shared_with(self, shared_with):
        self.shared_with = shared_with
        return self

    def set_is_hidden(self, is_hidden):
        self.is_hidden = is_hidden
        return self

    def set_is_public(self, is_public):
        self.is_public = is_public
        return self

    def set_is_cached(self, is_cached):
        self.is_cached = is_cached
        return self

    def set_ttl(self, ttl):
        self.ttl = ttl
        return self

    def set_ttb(self, ttb):
        self.ttb = ttb
        return self

    def set_ttr(self, ttr):
        self.ttr = ttr
        return self

    def set_ccd(self, ccd):
        self.ccd = ccd
        return self

    def set_is_binary(self, is_binary):
        self.is_binary = is_binary
        return self

    def set_is_encrypted(self, is_encrypted):
        self.is_encrypted = is_encrypted
        return self

    def set_data_signature(self, data_signature):
        self.data_signature = data_signature
        return self

    def set_shared_key_enc(self, shared_key_enc):
        self.shared_key_enc = shared_key_enc
        return self

    def set_pub_key_cs(self, pub_key_cs):
        self.pub_key_cs = pub_key_cs
        return self

    def set_encoding(self, encoding):
        self.encoding = encoding
        return self

    def set_value(self, value):
        self.value = value
        return self

    def set_metadata(self, metadata):
        self.is_hidden = metadata.is_hidden
        self.is_public = metadata.is_public
        self.is_cached = metadata.is_cached
        self.ttl = metadata.ttl
        self.ttb = metadata.ttb
        self.ttr = metadata.ttr
        self.ccd = metadata.ccd
        self.is_binary = metadata.is_binary
        self.is_encrypted = metadata.is_encrypted
        self.data_signature = metadata.data_signature
        self.shared_key_enc = metadata.shared_key_enc
        self.pub_key_cs = metadata.pub_key_cs
        self.encoding = metadata.encoding
        return self

    def with_at_key(self, at_key, value):
        self.set_key_name(at_key.name)
        self.set_shared_by(str(at_key.shared_by))
        if at_key.shared_with and str(at_key.shared_with):
            self.set_shared_with(str(at_key.shared_with))
        self.set_is_cached(at_key.metadata.is_cached)
        self.set_is_hidden(at_key.metadata.is_hidden)
        self.set_is_public(at_key.metadata.is_public)
        self.set_metadata(at_key.metadata)
        self.set_value(value)
        return self

    def build(self):
        if not self.key or not self.shared_by or not self.value:
            raise ValueError("key_name, shared_by, and value cannot be None or empty")
        full_key_name = self._build_at_key_str()
        metadata = self._build_metadata_str()
        return f"update{metadata}:{full_key_name} {str(self.value)}"

    def _build_at_key_str(self):
        s = ""
        if self.is_hidden:
            s += "_"
        if self.is_cached:
            s += "cached:"
        if self.is_public:
            s += "public:"
        if self.shared_with:
            s += f"{self.shared_with}:"
        s += self.key
        s += self.shared_by
        return s

    def _build_metadata_str(self):
        metadata = Metadata()
        metadata.ttl = self.ttl
        metadata.ttb = self.ttb
        metadata.ttr = self.ttr
        metadata.ccd = self.ccd
        metadata.is_binary = self.is_binary
        metadata.is_encrypted = self.is_encrypted
        metadata.data_signature = self.data_signature
        metadata.shared_key_enc = self.shared_key_enc
        metadata.pub_key_cs = self.pub_key_cs
        metadata.encoding = self.encoding
        return str(metadata)

class LlookupVerbBuilder:
    class Type(Enum):
        NONE = 0 
        METADATA = 1 
        ALL = 2 

    def __init__(self):
        self.key = None 
        self.shared_by = None 
        self.shared_with = None 
        self.is_hidden = None 
        self.is_public = None 
        self.is_cached = None 
        self.type = LlookupVerbBuilder.Type.NONE

    def set_key_name(self, key):
        self.key = key
        return self

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def set_shared_with(self, shared_with):
        self.shared_with = shared_with
        return self

    def set_is_hidden(self, is_hidden):
        self.is_hidden = is_hidden
        return self

    def set_is_public(self, is_public):
        self.is_public = is_public
        return self

    def set_is_cached(self, is_cached):
        self.is_cached = is_cached
        return self

    def set_type(self, type):
        self.type = type
        return self

    def with_at_key(self, at_key, type):
        self.set_key_name(at_key.name)
        self.set_shared_by(str(at_key.shared_by))
        if at_key.shared_with is not None and at_key.shared_with:
            self.set_shared_with(str(at_key.shared_with))
        self.set_is_hidden(at_key.metadata.is_hidden)
        self.set_is_public(at_key.metadata.is_public)
        self.set_is_cached(at_key.metadata.is_cached)
        self.set_type(type)
        return self

    def build(self):
        if not self.key or not self.shared_by:
            raise ValueError("key Name and shared By cannot be null or empty")

        s = "llookup:"
        if self.type == LlookupVerbBuilder.Type.METADATA:
            s += "meta:"
        elif self.type == LlookupVerbBuilder.Type.ALL:
            s += "all:"

        if self.is_hidden:
            s += "_"
        if self.is_cached:
            s += "cached:"
        if self.is_public:
            s += "public:"
        if self.shared_with:
            s += AtSign.format_atsign(self.shared_with) + ":"
        s += self.key
        s += AtSign.format_atsign(self.shared_by)

        return s

class LookupVerbBuilder:
    class Type(Enum):
        NONE = 0  
        METADATA = 1  
        ALL = 2  

    def __init__(self):
        self.key = None  
        self.shared_with = None  
        self.type = LookupVerbBuilder.Type.NONE

    def set_key_name(self, key):
        self.key = key
        return self

    def set_shared_with(self, shared_with):
        self.shared_with = shared_with
        return self

    def set_type(self, type):
        self.type = type
        return self

    def with_shared_key(self, shared_key, type):
        self.set_key_name(shared_key.name)
        self.set_shared_with(str(shared_key.shared_with))
        self.set_type(type)
        return self

    def build(self):
        if not self.key or not self.shared_with:
            raise ValueError("keyName and sharedWith cannot be null or empty")

        s = "lookup:"
        if self.type == LookupVerbBuilder.Type.METADATA:
            s += "meta:"
        elif self.type == LookupVerbBuilder.Type.ALL:
            s += "all:"

        s += self.key
        s += AtSign.format_atsign(self.shared_with)

        return s  


class PlookupVerbBuilder:
    class Type(Enum):
        NONE = 0  
        METADATA = 1  
        ALL = 2  

    def __init__(self):
        self.key = None  
        self.shared_by = None  
        self.bypass_cache = False  
        self.type = PlookupVerbBuilder.Type.NONE

    def set_key_name(self, key):
        self.key = key
        return self

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def set_type(self, type):
        self.type = type
        return self

    def set_bypass_cache(self, bypass_cache):
        self.bypass_cache = bypass_cache
        return self

    def with_at_key(self, at_key, type):
        self.set_key_name(at_key.name)
        self.set_shared_by(str(at_key.shared_by))
        self.set_type(type)
        return self

    def build(self):
        if not self.key or not self.shared_by:
            raise ValueError("key or sharedBy is null or empty")

        s = "plookup:"
        if self.bypass_cache:
            s += "bypassCache:true:"

        if self.type == PlookupVerbBuilder.Type.METADATA:
            s += "meta:"
        elif self.type == PlookupVerbBuilder.Type.ALL:
            s += "all:"

        s += self.key
        s += AtSign.format_atsign(self.shared_by)

        return s

class DeleteVerbBuilder:
    def __init__(self):
        self.key = None
        self.shared_by = None
        self.shared_with = ""
        self.is_hidden = False
        self.is_public = False
        self.is_cached = False

    def set_key_name(self, name):
        self.key = name
        return self

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def set_shared_with(self, shared_with):
        self.shared_with = shared_with
        return self

    def set_is_hidden(self, is_hidden):
        self.is_hidden = is_hidden
        return self

    def set_is_public(self, is_public):
        self.is_public = is_public
        return self

    def set_is_cached(self, is_cached):
        self.is_cached = is_cached
        return self

    def with_at_key(self, at_key):
        self.set_key_name(at_key.name)
        self.set_shared_by(str(at_key.shared_by))
        if at_key.shared_with and not str(at_key.shared_with).strip() == "":
            self.set_shared_with(str(at_key.shared_with))
        self.set_is_hidden(at_key.metadata.is_hidden)
        self.set_is_public(at_key.metadata.is_public)
        self.set_is_cached(at_key.metadata.is_cached)
        return self

    def build(self):
        if self.key is None or self.shared_by is None:
            raise ValueError("key or shared_by is None. These are required fields")

        s = "delete:"
        if self.is_hidden:
            s += "_"
        if self.is_cached:
            s += "cached:"
        if self.is_public:
            s += "public:"
        if self.shared_with and not self.shared_with.strip() == "":
            s += AtSign.format_atsign(self.shared_with) + ":"
        s += self.key
        s += AtSign.format_atsign(self.shared_by)
        return s 
    
class OperationEnum(Enum):
    UPDATE = "update"
    DELETE = "delete"
    REMOVE = "remove"
    #APPEND = "append"
    
class MessageTypeEnum(Enum):
    TEXT = "MessageType.text"
    KEY = "MessageType.key"
    
    def getMessageType(self):
        return self.value.split(".")[-1]
    
class NotifyVerbBuilder(VerbBuilder):
    def __init__(self):
        self.key = None
        self.shared_by = None
        self.shared_with = ""
        self.namespace = None
        self.is_hidden = False
        self.is_public = False
        self.is_cached = False
        self.value = None
        self.operation = None
        self.message_type = None
        self.metadata = None
        self.session_id = None

    def set_value(self, value):
        self.value = value
        return self

    def set_key_name(self, name):
        self.key = name
        return self

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def set_shared_with(self, shared_with):
        self.shared_with = shared_with
        return self

    def set_is_hidden(self, is_hidden):
        self.is_hidden = is_hidden
        return self

    def set_is_public(self, is_public):
        self.is_public = is_public
        return self

    def set_is_cached(self, is_cached):
        self.is_cached = is_cached
        return self
    
    def set_operation(self, operation):
        self.operation = OperationEnum(operation)
        return self
        
    def set_metadata(self, metadata):
        self.metadata = metadata
        return self
        
    def set_message_type(self, message_type):
        self.message_type = MessageTypeEnum(message_type)
        return self
    
    def set_namespace(self, namespace):
        self.namespace = namespace
        return self
    
    def set_session_id(self, session_id):
        self.session_id = session_id
        return self

    def with_at_key(self, at_key, encrypted_value, operation=OperationEnum.UPDATE, session_id=None):
        self.set_key_name(at_key.name)
        self.set_shared_by(str(at_key.shared_by))
        self.set_shared_with(str(at_key.shared_with))
        self.set_is_hidden(at_key.metadata.is_hidden)
        self.set_is_public(at_key.metadata.is_public)
        self.set_is_cached(at_key.metadata.is_cached)
        self.set_metadata(at_key.metadata)
        self.set_value(encrypted_value)
        self.set_namespace(at_key.namespace)
        self.set_session_id(session_id)
        self.operation = operation
        if self.message_type is None:
            self.message_type = MessageTypeEnum.KEY
        return self
        

    def build(self):
        if self.key is None or (self.shared_with is None and not self.is_public):
            raise ValueError("key is None or, you have a public key with no shared_with. These are required fields")
        s = f"notify:id:{self.session_id}:"
        if self.operation:
            s+= f"{str(self.operation.value)}"
        if self.metadata:
            s+= str(self.metadata) + ":"
        if self.shared_with:
            s += AtSign.format_atsign(self.shared_with) + ":"
        s += self.key
        if self.namespace:
            s+= self.namespace
        s += str(AtSign.format_atsign(self.shared_by)) + ":"
        s += self.value
        return s
