import ssl
from threading import Thread
import threading
import time
import json
import traceback

from ..common.atsign import AtSign
from .notification.atevents import AtEvent, AtEventType
from ..util.syncdecorator import synchronized
from ..util.timeutil import TimeUtil
from .address import Address
from .atsecondaryconnection import AtSecondaryConnection
import queue

class AtMonitorConnection(AtSecondaryConnection):
    last_received_time: int = 0
    running: bool = False
    should_be_running: bool = False
    
    def __init__(self, queue:queue.Queue, atsign:AtSign, address: Address, context:ssl.SSLContext=ssl.create_default_context(), verbose:bool=True, regex=".*"):
        self.atsign = atsign
        self.queue = queue
        self.regex = regex
        self._verbose = verbose
        self.should_be_running_lock = threading.Lock()
        self.running_lock = threading.Lock()
        super().__init__(address, context, verbose)
        self._last_heartbeat_sent_time = TimeUtil.current_time_millis()
        self._last_heartbeat_ack_time = TimeUtil.current_time_millis()
        self._heartbeat_interval_millis = 30000
        self.start_heart_beat()

    def start_heart_beat(self):
        # Daemon: an abandoned connection's heartbeat must not keep the process alive.
        self._heartbeat_thread = threading.Thread(target=self._start_heart_beat, daemon=True)
        self._heartbeat_thread.start()
    
    def _start_heart_beat(self):
        while True:
            self.should_be_running_lock.acquire()
            if self.should_be_running:
                self.should_be_running_lock.release()
                if (not self.running) or (self._last_heartbeat_sent_time - self._last_heartbeat_ack_time >= self._heartbeat_interval_millis):
                    try:
                        print("Monitor heartbeats not being received")
                        self.stop_monitor()
                        wait_start_time = TimeUtil.current_time_millis()
                        self.running_lock.acquire(blocking=1)
                        entered = False
                        print((TimeUtil.current_time_millis() - wait_start_time) < 5000)
                        while self.running and ((TimeUtil.current_time_millis() - wait_start_time) < 5000):
                            entered = True
                            self.running_lock.release()
                            print("Wait 5 seconds for monitor to stop")
                            try:
                                time.sleep(1)
                            except Exception as ignore:
                                pass
                        if not entered:
                            self.running_lock.release()
                            entered = False
                        self.running_lock.acquire(blocking=1)
                        if self.running:
                            print("Monitor thread has not stopped, but going to start another one anyway")
                        self.running_lock.release()
                        self.start_monitor()
                    except Exception as e:
                        print("Monitor restart failed "+ str(e))  
                else:
                    if TimeUtil.current_time_millis() - self._last_heartbeat_sent_time > self._heartbeat_interval_millis:
                        try:
                            self.execute_command(command="noop:0", retry_on_exception=False, read_the_response=False)
                            self._last_heartbeat_sent_time = TimeUtil.current_time_millis()
                        except Exception as ignore:
                            # Can't do anything, the heartbeat loop will take care of restarting the monitor connection
                            pass
            else:
                self.should_be_running_lock.release()
            try:
                time.sleep(self._heartbeat_interval_millis / 6000) # 6 * 1000 (from ms to s)
            except Exception as ignore:
                pass
                
    def start_monitor(self):
        self._last_heartbeat_sent_time = self._last_heartbeat_ack_time = TimeUtil.current_time_millis()
        
        self.should_be_running_lock.acquire(blocking=1)
        self.should_be_running = True
        self.should_be_running_lock.release()
        
        self.running_lock.acquire(blocking=1)
        if not self.running:
            self.running = True
            self.running_lock.release()
            if not self._connected:
                try:
                    self._connect()
                except Exception as e:
                    print("startMonitor failed to connect to secondary : " + str(e))
                    traceback.print_exc()
                    self.running_lock.acquire(blocking=1)
                    self.running = False
                    self.running_lock.release()
                    return False
            self._run()
        else:
            self.running_lock.release()
        return True
    
    def stop_monitor(self):
        self.should_be_running_lock.acquire(blocking=1)
        self.should_be_running = False
        self.should_be_running_lock.release()
        
        self._last_heartbeat_sent_time = self._last_heartbeat_ack_time = TimeUtil.current_time_millis()
        self.disconnect()

    @staticmethod
    def _is_shared_key_notification(atsign, key):
        """True if `key` is an incoming shared-key notification for `atsign`.

        e.g. "@alice:shared_key@bob" when we (alice) are the receiver. Uses
        to_string() — calling the bound method, not stringifying it.
        """
        return key.startswith(atsign.to_string() + ":shared_key@")

    def _run(self):
        what = ""
        first = True
        try:
            monitor_cmd = "monitor:" + str(self.last_received_time) + " " + self.regex
            what = "send monitor command " + monitor_cmd
            self.execute_command(command=monitor_cmd, retry_on_exception=True, read_the_response=False)
            print("Monitor started on " + str(self.atsign.to_string()))
            entered = False
            self.should_be_running_lock.acquire(blocking=1)
            while self.should_be_running:
                self.should_be_running_lock.release()
                entered = True
                first = False
                what = "read from connection"
                response = self._stream_reader.readline()
                if self._verbose and response != b"":
                    print("\tRCVD (MONITOR): " + str(response.decode()))
                    
                event_type = AtEventType.NONE
                event_data = {}
                what = "parse monitor message"
                try:
                    if response.startswith(b"data:ok"):
                        event_type = AtEventType.MONITOR_HEARTBEAT_ACK
                        event_data["key"] = "__heartbeat__"
                        event_data["value"] = response.decode()[len("data:"):]
                        self._last_heartbeat_ack_time = TimeUtil.current_time_millis()
                    elif response.startswith(b"data:"):
                        event_type = AtEventType.MONITOR_EXCEPTION
                        event_data["key"] = "__monitorException__"
                        event_data["value"] = response.decode()
                        event_data["exception"] = "Unexpected 'data:' message from server"
                    elif response.startswith(b"error:"):
                        event_type = AtEventType.MONITOR_EXCEPTION
                        event_data["key"] = "__monitorException__"
                        event_data["value"] = response.decode()
                        event_data["exception"] = "Unexpected 'error:' message from server"
                    elif response.startswith(b"notification:"):
                        event_data = json.loads(response.decode()[len("notification:"):])
                        uuid = str(event_data.get("id"))
                        operation = str(event_data.get("operation"))
                        key = str(event_data.get("key"))
                        if "epochMillis" in event_data:
                            self.last_received_time = int(event_data.get("epochMillis"))
                        else:
                            self.last_received_time = TimeUtil.current_time_millis()
                        if uuid == "-1":
                            event_type = AtEventType.STATS_NOTIFICATION
                        elif operation == "update":
                            if self._is_shared_key_notification(self.atsign, key):
                                event_type = AtEventType.SHARED_KEY_NOTIFICATION
                            else:
                                event_type = AtEventType.UPDATE_NOTIFICATION
                        elif operation == "delete":
                            event_type = AtEventType.DELETE_NOTIFICATION
                        else:
                            event_type = AtEventType.MONITOR_EXCEPTION
                            event_data["key"] = "__monitorException__"
                            event_data["value"] = response.decode()
                            event_data["exception"] = "Unknown notification operation " + str(operation)
                    else:
                        event_type = AtEventType.MONITOR_EXCEPTION
                        event_data["key"] = "__monitorException__"
                        event_data["value"] = response.decode()
                        event_data["exception"] = "Malformed response from server"
                except Exception as e:
                    print(e)
                    event_type = AtEventType.MONITOR_EXCEPTION
                    event_data["key"] = "__monitorException__"
                    event_data["value"] = response.decode()
                    event_data["exception"] = str(e)
                    traceback.print_exc()

                at_event = AtEvent(event_type, event_data)
                self.queue.put(at_event)
                
                self.should_be_running_lock.acquire(blocking=1)
                entered = False
            if not entered:
                self.should_be_running_lock.release()
                entered = False
        except Exception as e:
            traceback.print_exc()
            self.should_be_running_lock.acquire(blocking=1)
            if not self.should_be_running:
                self.should_be_running_lock.release()
            else:
                self.should_be_running_lock.release()
                print("Monitor failed to " + what + " : " + str(e))
                traceback.print_exc()
                print("Monitor ending. Monitor heartbeat thread should restart the monitor shortly")
                self.disconnect()
        finally:
            self.running_lock.acquire(blocking=1)
            self.running = False
            self.running_lock.release()
            
            self.disconnect()
            
    def _connect(self):
        """
        Establish a connection to the secondary server.
        """
        super().connect()
        if self._verbose:
            print("Secondary Connection Successful")
