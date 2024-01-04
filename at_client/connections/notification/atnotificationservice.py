import base64, threading, time, traceback   
from queue import Empty, Queue
from at_client.common.keys import AtKey, SharedKey
from at_client.connections.atmonitorconnection import AtMonitorConnection
from at_client.connections.notification.atevents import AtEvent, AtEventType
from at_client.util.authutil import AuthUtil
from at_client.util.encryptionutil import EncryptionUtil
from at_client.util.keysutil import KeysUtil

class AtNotificationService:
    
    
    def __init__(self, at_client, verbose = False):
        self._notification_list = []
        self.at_client = at_client
        self.verbose = verbose
        self.monitor_connection = at_client.monitor_connection
        self.queue = at_client.queue
        if at_client.queue != None:
            self.decrypted_events = Queue(at_client.queue.maxsize)
        else:
            raise Exception("You must assign a Queue object to the queue parameter of AtClient class")

    def start_monitor(self, regex="", decrypt_events=True):
        '''
        Starts the monitor connection and starts listening for events.
        Will start a thread to decrypt events if decrypt_events is True.
        '''
        threading.Thread(target=self._start_monitor, args=(regex,)).start()
        while self.monitor_connection == None:
            time.sleep(0.1)
        if decrypt_events:
            threading.Thread(target=self._decrypt_events, args=(self.queue,)).start()
            
            
    def stop_monitor(self):
        '''
        Stops the monitor connection.
        '''
        if self.queue != None:
            should_be_running_lock
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
        
        
    def get_decrypted_events(self):
        '''
        Returns a generator that yields decrypted events.
        
        Example: 
        for event in at_client.get_decrypted_events():
            do_something_with_event(event)
        '''
        if self.decrypted_events != None:
            while True:
                try:
                    at_event = self.decrypted_events.get(block=False)
                    yield at_event
                except Empty:
                    break
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")

    def _start_monitor(self, regex=""):
        if self.queue != None:
            global should_be_running_lock 
            should_be_running_lock = threading.Lock()
            what = ""
            try:
                if self.monitor_connection == None:
                    what = "construct an AtMonitorConnection"
                    self.monitor_connection = AtMonitorConnection(queue=self.queue, atsign=self.at_client.atsign, address=self.at_client.secondary_address, verbose=self.verbose)
                    self.monitor_connection.connect()
                    AuthUtil.authenticate_with_pkam(self.monitor_connection, self.at_client.atsign, self.at_client.keys)
                    should_be_running_lock.acquire(blocking=1)
                if not self.monitor_connection.running:
                    should_be_running_lock.release()
                    what = "call monitor_connection.start_monitor()"
                    self.monitor_connection.start_monitor(regex)
                else:
                    should_be_running_lock.release()
            except Exception as e:
                print("SEVERE: failed to " + what + " : " + str(e))
                traceback.print_exc()
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")
        
  # This method is meant to be run in a separate thread
    def _decrypt_events(self, queue):   
        while True:
            try:
                at_event = queue.get(block=False)
                event_type = at_event.event_type    
                if event_type == AtEventType.UPDATE_NOTIFICATION or event_type == AtEventType.UPDATE_NOTIFICATION_TEXT:
                    self._handle_event(queue, at_event)
                
            except Empty:
                pass
            except Exception as e:
                print("SEVERE: failed to decrypt event : " + str(e))
                break

    def _handle_event(self, queue, at_event):
        if queue != None:
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
                            encryption_key_shared_by_other = self.at_client.get_encryption_key_shared_by_other(SharedKey.from_string(key=key))
                            decrypted_value = EncryptionUtil.aes_decrypt_from_base64(encrypted_text=encrypted_value.encode(), self_encryption_key=encryption_key_shared_by_other, iv=base64.b64decode(ivNonce))
                            new_event_data = dict(event_data)
                            new_event_data["decryptedValue"] = decrypted_value
                            new_at_event = AtEvent(AtEventType.DECRYPTED_UPDATE_NOTIFICATION, new_event_data)
                            self.decrypted_events.put(new_at_event)
                            self.at_client.secondary_connection.execute_command("notify:remove:" + event_data["id"])
                        except Exception as e:
                            print(str(time.time()) + ": caught exception " + str(e) + " while decrypting received data with key name [" + key + "]")
            except Empty:
                pass
        else:
            raise Exception("You must assign a Queue object to the queue paremeter of AtClient class")