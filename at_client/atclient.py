import base64
import json
from queue import Empty, Queue
import time
import traceback

from at_client.connections.notification.atevents import AtEvent, AtEventType


from .common.atsign import AtSign
from .util.verbbuilder import *
from .util.encryptionutil import EncryptionUtil
from .util.keysutil import KeysUtil
from .common.metadata import Metadata
from .exception.atexception import *
from .connections.atrootconnection import AtRootConnection
from .connections.atsecondaryconnection import AtSecondaryConnection
from .connections.atmonitorconnection import AtMonitorConnection
from .util.atconstants import *
from .connections.address import Address
from .common.keys import AtKey, Keys, SharedKey, PrivateHiddenKey, PublicKey, SelfKey
from .util.authutil import AuthUtil

class AtClient(ABC):
    def __init__(self, atsign:AtSign, root_address:Address=Address("root.atsign.org", 64), secondary_address:Address=None, queue:Queue=None, verbose:bool = False):
        self.atsign = atsign
        self.queue = queue
        self.monitor_connection = None
        self.keys = KeysUtil.load_keys(atsign)
        self.verbose = verbose
        if secondary_address is None:
            self.root_connection = AtRootConnection.get_instance(host=root_address.host, 
                                                            port=root_address.port, 
                                                            verbose=verbose)
            secondary_address = self.root_connection.find_secondary(atsign)
        self.secondary_address = secondary_address
        self.secondary_connection = AtSecondaryConnection(secondary_address, verbose=verbose)
        self.secondary_connection.connect()
        AuthUtil.authenticate_with_pkam(self.secondary_connection, self.atsign, self.keys)
        self.authenticated = True
    
    def get_at_keys(self, regex, fetch_metadata):
        scan_command = ScanVerbBuilder().set_regex(regex).set_show_hidden(True).build()
        try:
            scan_raw_response = self.secondary_connection.execute_command(scan_command, True).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute : {scan_command} : {e}")
        
        keys_list = []
        if len(scan_raw_response) > 0:
            keys_list = json.loads(scan_raw_response)

        at_keys = []
        for at_key_raw in keys_list:
            at_key = Keys.from_string(at_key_raw)
            if fetch_metadata:
                llookup_command = "llookup:meta:" + at_key_raw
                try:
                    llookup_meta_response = self.secondary_connection.execute_command(llookup_command, read_the_response=True).get_raw_data_response()
                except Exception as e:
                    raise AtSecondaryConnectException(f"Failed to execute : {llookup_command} : {e}")
                
                try:
                    at_key.metadata = Metadata.squash(at_key.metadata, Metadata.from_json(llookup_meta_response))
                except Exception as e:
                    raise AtResponseHandlingException(f"Failed to parse JSON : {llookup_meta_response} : {e}")
            
            at_keys.append(at_key)
        
        return at_keys
    
    def is_authenticated(self):
        return self.authenticated
    
    def get_public_encryption_key(self, shared_with):
        raw_response = None

        command = "plookup:publickey" + shared_with.to_string()
        try:
            response = self.secondary_connection.execute_command(command, False)
        except AtSecondaryNotFoundException as e: raise e
        except AtSecondaryConnectException as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        if response.is_error():
            ex = response.get_exception()
            if isinstance(ex, AtKeyNotFoundException) or isinstance(ex, AtInternalServerException): 
                return None
            else:
                raise ex
        else:
            return response.get_raw_data_response()

    
    def create_shared_encryption_key(self, shared_key: SharedKey):
        their_public_encryption_key = self.get_public_encryption_key(shared_key.shared_with)
        if their_public_encryption_key is None:
            raise AtKeyNotFoundException(f" public key {shared_key.shared_with.to_string()} not found but service is running - maybe that AtSign has not yet been onboarded")

        aes_key = ""
        try:
            aes_key = EncryptionUtil.generate_aes_key_base64()
        except Exception as e:
            raise AtEncryptionException(f"Failed to generate AES key for sharing with {shared_key.shared_with}")

        step = ""
        try:
            step = "encrypt new shared key with their public key"
            encrypted_for_other = EncryptionUtil.rsa_encrypt_to_base64(aes_key, their_public_encryption_key)

            step = "encrypt new shared key with our public key"
            encrypted_for_us = EncryptionUtil.rsa_encrypt_to_base64(aes_key, self.keys.get(KeysUtil.encryption_public_key_name))

            step = "save encrypted shared key for us"
            command1 = "update:" + "shared_key." + shared_key.shared_with.without_prefix + shared_key.shared_by.to_string()\
                                    + " " + encrypted_for_us
            self.secondary_connection.execute_command(command1, True)

            step = "save encrypted shared key for them"
            ttr = 24 * 60 * 60 * 1000
            command2 = "update:ttr:" + str(ttr) + ":" + shared_key.shared_with.to_string() + ":shared_key" + shared_key.shared_by.to_string()\
                                    + " " + encrypted_for_other
            self.secondary_connection.execute_command(command2, True)
        except Exception as e:
            raise AtEncryptionException(f"Failed to {step} - {e}")

        return aes_key
    
    def get_encryption_key_shared_by_me(self, key: SharedKey):
        response = None
        to_lookup = "shared_key." + key.shared_with.without_prefix + self.atsign.to_string()

        command = "llookup:" + to_lookup
        try:
            response = self.secondary_connection.execute_command(command, False)
        except AtException as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        if response.is_error():
            if isinstance(response.get_exception(), AtKeyNotFoundException):
                return self.create_shared_encryption_key(key)
            else:
                raise response.get_exception()

        try:
            return EncryptionUtil.rsa_decrypt_from_base64(response.get_raw_data_response(), self.keys[KeysUtil.encryption_private_key_name])
        except Exception as e:
            raise AtDecryptionException(f"Failed to decrypt {to_lookup} - e")
        
    def get_encryption_key_shared_by_other(self, shared_key: SharedKey):
        shared_shared_key_name = shared_key.get_shared_shared_key_name()

        shared_key_value = self.keys.get(shared_shared_key_name)
        if shared_key_value is not None:
            return shared_key_value

        lookup_command = "lookup:" + "shared_key" + str(shared_key.shared_by)
        raw_response = None
        try:
            raw_response = self.secondary_connection.execute_command(lookup_command, True)
        except AtKeyNotFoundException as e: raise e
        except AtException as e:
            raise AtSecondaryConnectException(f"Failed to execute {lookup_command} - {e}")

        shared_shared_key_decrypted_value = None
        try:
            shared_shared_key_decrypted_value = EncryptionUtil.rsa_decrypt_from_base64(raw_response.get_raw_data_response(), self.keys[KeysUtil.encryption_private_key_name])
        except Exception as e:
            raise AtDecryptionException(f"Failed to decrypt the shared_key with our encryption private key - {e}")

        self.keys[shared_shared_key_name] =  shared_shared_key_decrypted_value

        return shared_shared_key_decrypted_value


    def put(self, key, value):
        if isinstance(key, SharedKey):
            return self._put_shared_key(key, value)
        elif isinstance(key, SelfKey):
            return self._put_self_key(key, value)
        elif isinstance(key, PublicKey):
            return self._put_public_key(key, value)
        else:
            raise NotImplementedError(f"No implementation found for key type: {type(key)}")

    def _put_self_key(self, key: SelfKey, value: str):
        key.metadata.data_signature = EncryptionUtil.sign_sha256_rsa(value, self.keys[KeysUtil.encryption_private_key_name])

        try:
            cipher_text = EncryptionUtil.aes_encrypt_from_base64(value, self.keys[KeysUtil.self_encryption_key_name])
        except Exception as e:
            raise AtEncryptionException(f"Failed to encrypt value with self encryption key - {e}")
        
        command = UpdateVerbBuilder().with_at_key(key, cipher_text).build()
        try:
            return self.secondary_connection.execute_command(command).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

    def _put_public_key(self, key: PublicKey, value: str):
        key.metadata.data_signature = EncryptionUtil.sign_sha256_rsa(value, self.keys[KeysUtil.encryption_private_key_name])

        command = UpdateVerbBuilder().with_at_key(key, value).build()

        try:
            return self.secondary_connection.execute_command(command).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")
        
    def _put_shared_key(self, key: SharedKey, value: str):
        if self.atsign != key.shared_by:
            raise AtIllegalArgumentException(f"sharedBy is [{key.shared_by}] but should be this client's atSign [{self.atsign}]")

        what = ""
        cipher_text = None
        try:
            what = "fetch/create shared encryption key"
            share_to_encryption_key = self.get_encryption_key_shared_by_me(key)

            what = "encrypt value with shared encryption key"
            cipher_text = EncryptionUtil.aes_encrypt_from_base64(value, share_to_encryption_key)
        except Exception as e:
            raise AtEncryptionException(f"Failed to {what} - {e}")

        command = f"update{key.metadata}:{key} {cipher_text}"

        try:
            return self.secondary_connection.execute_command(command, True).get_raw_data_response()
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")
    
    def get(self, key):
        if isinstance(key, SharedKey):
            return self._get_shared_key(key)
        elif isinstance(key, SelfKey):
            return self._get_self_key(key)
        elif isinstance(key, PublicKey):
            return self._get_public_key(key)
        else:
            raise NotImplementedError(f"No implementation found for key type: {type(key)}")
        
    def get_lookup_response(self, command: str):
        try:
            response = self.secondary_connection.execute_command(command, True)
        except (AtKeyNotFoundException, AtInternalServerException) as e: raise e
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        fetched = None
        try:
            fetched = json.loads(response.get_raw_data_response())
        except Exception as e:
            raise AtResponseHandlingException(f"Failed to parse JSON {response.get_raw_data_response()} - {e}")

        return fetched

        
    def _get_self_key(self, key: SelfKey):
        command = LlookupVerbBuilder().with_at_key(key, LlookupVerbBuilder.Type.ALL).build()

        fetched = self.get_lookup_response(command)

        decrypted_value = None
        encrypted_value = fetched["data"]
        self_encryption_key = self.keys[KeysUtil.self_encryption_key_name]
        try:
            decrypted_value = EncryptionUtil.aes_decrypt_from_base64(encrypted_value, self_encryption_key)
        except Exception as e:
            raise AtDecryptionException(f"Failed to {command} - {e}")

        key.metadata = Metadata.squash(Metadata.from_dict(fetched["metaData"]), key.metadata)

        return decrypted_value
    
    def _get_public_key(self, key: PublicKey):
        command = ""
        if self.atsign == key.shared_by:
            command = LlookupVerbBuilder().with_at_key(key, LlookupVerbBuilder.Type.ALL).build()
        else:
            builder = PlookupVerbBuilder()
            command = builder.with_at_key(key, PlookupVerbBuilder.Type.ALL).build()

        fetched = self.get_lookup_response(command)

        key.metadata = Metadata.squash(Metadata.from_dict(fetched["metaData"]), key.metadata)
        key.metadata.is_cached = "cached:" in fetched["key"]

        return fetched["data"]
    
    def _get_shared_key(self, key: SharedKey):
        if key.shared_by == self.atsign:
            return self._get_shared_by_me_with_other(key)
        else:
            return self._get_shared_by_other_with_me(key)

    def _get_shared_by_me_with_other(self, shared_key: SharedKey):
        share_encryption_key = self.get_encryption_key_shared_by_me(shared_key)

        raw_response = None
        command = "llookup:" + str(shared_key)
        try:
            raw_response = self.secondary_connection.execute_command(command, True)
        except (AtKeyNotFoundException, AtInternalServerException) as e: raise e
        except AtSecondaryConnectException as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        try:
            return EncryptionUtil.aes_decrypt_from_base64(raw_response.get_raw_data_response(), share_encryption_key)
        except Exception as e:
            raise AtDecryptionException(f"Failed to decrypt value with shared encryption key - {e}")

    def _get_shared_by_other_with_me(self, shared_key:SharedKey):
        what = None
        share_encryption_key = self.get_encryption_key_shared_by_other(shared_key)

        raw_response = None
        command = "lookup:" + shared_key.name
        if shared_key.get_namespace() is not None and shared_key.get_namespace():
            command += "." + shared_key.get_namespace()
        command += str(shared_key.shared_by)
        try:
            raw_response = self.secondary_connection.execute_command(command, True)
        except Exception as e:
            raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")

        what = "decrypt value with shared encryption key"
        try:
            return EncryptionUtil.aes_decrypt_from_base64(raw_response.get_raw_data_response(), share_encryption_key)
        except Exception as e:
            raise AtDecryptionException(f"Failed to {what} - {e}")

    def delete(self, key):
        if isinstance(key, SharedKey) or isinstance(key, SelfKey) or isinstance(key, PublicKey):
            command = DeleteVerbBuilder().with_at_key(key).build()
            try:
                return self.secondary_connection.execute_command(command).get_raw_data_response()
            except Exception as e:
                raise AtSecondaryConnectException(f"Failed to execute {command} - {e}")
        else:
            raise NotImplementedError(f"No implementation found for key type: {type(key)}")
    
    def __del__(self):
        if self.secondary_connection:
            self.secondary_connection.disconnect()

    def start_monitor(self, regex=".*"):
        if self.queue != None:
            global should_be_running_lock
            what = ""
            try:
                if self.monitor_connection == None:
                    what = "construct an AtMonitorConnection"
                    self.monitor_connection = AtMonitorConnection(queue=self.queue, atsign=self.atsign, address=self.secondary_address, verbose=self.verbose, regex=regex)
                    self.monitor_connection.connect()
                    AuthUtil.authenticate_with_pkam(self.monitor_connection, self.atsign, self.keys)
                should_be_running_lock.acquire(blocking=1)
                if not self.monitor_connection.running:
                    should_be_running_lock.release()
                    what = "call monitor_connection.start_monitor()"
                    self.monitor_connection.start_monitor()
                else:
                    should_be_running_lock.release()
            except Exception as e:
                print("SEVERE: failed to " + what + " : " + str(e))
                traceback.print_exc()
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")
        
    def stop_monitor(self):
        if self.queue != None:
            global should_be_running_lock
            what = ""
            try:
                if self.monitor_connection == None:
                    return
                should_be_running_lock.acquire(blocking=1)
                if not self.monitor_connection.running:
                    should_be_running_lock.release()
                    what = "call monitor_connection.stop_monitor()"
                    self.monitor_connection.stop_monitor()
                else:
                    should_be_running_lock.release()
            except Exception as e:
                print("SEVERE: failed to " + what + " : " + str(e))
                traceback.print_exc()
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")

    def handle_event(self, queue, at_event):
        if self.queue != None:
            try:
                event_type = at_event.event_type
                event_data = at_event.event_data
                
                if event_type == AtEventType.SHARED_KEY_NOTIFICATION:
                    if event_data["value"] != None:
                        shared_shared_key_name = event_data["key"]
                        shared_shared_key_encrypted_value = event_data["value"]
                        try:
                            shared_key_decrypted_value = EncryptionUtil.rsa_decrypt_from_base64(shared_shared_key_encrypted_value, self.keys[KeysUtil.encryption_private_key_name])
                            self.keys[shared_shared_key_name] = shared_key_decrypted_value
                        except Exception as e:
                            print(str(time.time()) + ": caught exception " + str(e) + " while decrypting received shared key " + shared_shared_key_name)
                elif event_type == AtEventType.UPDATE_NOTIFICATION:
                    if event_data["value"] != None:
                        key = event_data["key"]
                        encrypted_value = event_data["value"]
                        ivNonce = event_data["metadata"]["ivNonce"]
                        try:
                            encryption_key_shared_by_other = self.get_encryption_key_shared_by_other(SharedKey.from_string(key=key))
                            decrypted_value = EncryptionUtil.aes_decrypt_from_base64(encrypted_text=encrypted_value.encode(), self_encryption_key=encryption_key_shared_by_other, iv=base64.b64decode(ivNonce))
                            new_event_data = dict(event_data)
                            new_event_data["decryptedValue"] = decrypted_value
                            new_at_event = AtEvent(AtEventType.DECRYPTED_UPDATE_NOTIFICATION, new_event_data)
                            queue.put(new_at_event)
                        except Exception as e:
                            print(str(time.time()) + ": caught exception " + str(e) + " while decrypting received data with key name [" + key + "]")
            except Empty:
                pass
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")
        
    def notify(self, at_key : AtKey, value, operation = OperationEnum.UPDATE, session_id = str(uuid.uuid4())):
        iv = at_key.metadata.iv_nonce
        shared_key = self.get_encryption_key_shared_by_me(at_key)
        encrypted_value = EncryptionUtil.aes_encrypt_from_base64(value, shared_key, iv)
        command = NotifyVerbBuilder().with_at_key(at_key, encrypted_value, operation, session_id).build()
        notify_result = self.secondary_connection.execute_command(command)
        return notify_result.get_raw_data_response()
        
    
    
