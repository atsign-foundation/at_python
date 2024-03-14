import os, sys
from queue import Queue, Empty
import threading

if os.path.basename(os.getcwd()) == "examples":
    base_dir = ".."
else:
    base_dir = "."

sys.path.append(base_dir)
sys.path.append(f"{base_dir}/at_client/common")
sys.path.append(f"{base_dir}/at_client/connections")
sys.path.append(f"{base_dir}/at_client/util")

from at_client import AtClient
from at_client.common import AtSign
from at_client.common.keys import Keys, SharedKey
from at_client.util.keystringutil import KeyStringUtil, KeyType
from at_client.connections.notification.atevents import AtEvent, AtEventType
from at_client.util.atconstants import *

shared_queue = Queue()

def print_help_instructions():
    print()
    print("AtClient REPL")
    print("  Notes:")
    print("    1) By default, REPL treats input as atProtocol commands. Use / for additional commands listed below")
    print("    2) In the usage examples below, it is assumed that the atSign being used is @alice@")
    print()
    print("  help or /help - print this help message")
    print()
    print("  /scan [regex] - scan for all records, or all records whose keyNames match the regex (e.g. _scan test@alice.*)")
    print()
    print("  /put <atKeyName> <value> - create or update a record with the given atKeyName and with the supplied value - for example:")
    print("    /put test@alice secret secrets will create or update a 'self' record (a record private just to @alice)")
    print("    /put @bob:test@alice Hello, Bob! will create or update a record encrypted for, and then shared with, @bob")
    print()
    print("  /get <atKeyName> - retrieve a value from the record with this atKeyName - for example:")
    print("    /get <atKeyName> - retrieve a value from the record with this atKeyName (e.g. _get test@alice)")
    print()
    print("  /delete <atKeyName> - delete the record with this atKeyName (e.g. _delete test@alice)")
    print()
    print("  NOTE: put, get, and delete will append the current atSign to the atKeyName if not supplied")
    print()


def handle_event(queue, client):
    while True:
        try:
            at_event = queue.get(block=False)
            client.handle_event(queue, at_event)
            event_type = at_event.event_type
            event_data = at_event.event_data
            print("\t  => " + " REPL received event: " + str(event_type) + "\n\t\t\t" + str(event_data) + "\n")
            sk = None
            if event_type == AtEventType.DECRYPTED_UPDATE_NOTIFICATION:
                key = event_data["key"]
                sk = SharedKey.from_string(key=key)
                value = event_data["value"]
                decrypted_value = str(event_data["decryptedValue"])
                print("  => Notification ==>  Key: [" + str(sk) + "]  ==> EncryptedValue [" + str(value) + "]  ==> DecryptedValue [" + decrypted_value + "]")
            elif event_type == AtEventType.UPDATE_NOTIFICATION_TEXT:
                print(str(event_data))
            elif event_type == AtEventType.UPDATE_NOTIFICATION:
                try:
                    sk = SharedKey.from_string(str(event_data["key"]))
                    
                except Exception as e:
                    print("Failed to retrieve " + str(sk) + " : " + str(e))
        except Empty:
            pass
    
def main():
        
    atSignStr = 'NOT SET'
    
    while True:
        print("Welcome! What would you like to do?\n"
            "\t1) Change atSign (presently " + atSignStr + ")\n"
            "\t2) Connect to " + atSignStr + " and interact with it\n"
            "\t3) Exit")
        
        opt=input("> ")
        
        if int(opt) == 1:
            atSignStr=input("atSign:")
        elif int(opt) == 2:
            if atSignStr != '' and atSignStr != 'NOT SET':
                print('Connecting to ' + atSignStr + "...")
                atSign = AtSign(atSignStr)
                
                global shared_queue
                client = AtClient(atsign=atSign, verbose=True, queue=shared_queue)
                
                threading.Thread(target=handle_event, args=(shared_queue,client,)).start()
                threading.Thread(target=client.start_monitor, args=()).start()
                
                command = ''
                while command!= '/exit':
                    if client.authenticated:
                        command = input("@" + atSignStr + "@")
                    else:
                        command = input("@")
                    command = command.strip()
                    if command != '' and (command == "help" or command.startswith("_") or command.startswith("/") or command.startswith("\\")):
                        if command != "help":
                            command = command[1:]
                        parts = command.split(" ")
                        verb = parts[0]
                        try:
                            if verb == "help":
                                print_help_instructions()
                            elif verb == "get":
                                fullKeyName = parts[1]
                                keyStringUtil = KeyStringUtil(full_key_name=fullKeyName)
                                keyType = keyStringUtil.get_key_type()
                                if keyType == KeyType.PUBLIC_KEY:
                                    pk = Keys.from_string(fullKeyName)
                                    value = client.get(key=pk)
                                    print("  => " + value)
                                elif keyType == KeyType.SELF_KEY:
                                    sk = Keys.from_string(fullKeyName)
                                    value = client.get(key=sk)
                                    print("  => " + value)
                                elif keyType == KeyType.SHARED_KEY:
                                    sk = SharedKey.from_string(fullKeyName)
                                    value = client.get(key=sk)
                                    print("  => " + value)
                                elif keyType == KeyType.PRIVATE_HIDDEN_KEY:
                                    print("PrivateHiddenKey is not implemented yet")
                                else:
                                    raise Exception("Could not evaluate the key type of: " + fullKeyName)
                            elif verb == "put":
                                fullKeyName = parts[1]
                                value = command[len(verb) + len(fullKeyName) + 2:].strip()
                                keyStringUtil = KeyStringUtil(full_key_name=fullKeyName)
                                keyType = keyStringUtil.get_key_type()
                                if keyType == KeyType.PUBLIC_KEY:
                                    pk = Keys.from_string(fullKeyName)
                                    data = client.put(key=pk, value=value)
                                    print("  => " + data)
                                elif keyType == KeyType.SELF_KEY:
                                    sk = Keys.from_string(fullKeyName)
                                    data = client.put(key=sk, value=value)
                                    print("  => " + data)
                                elif keyType == KeyType.SHARED_KEY:
                                    sk = SharedKey.from_string(fullKeyName)
                                    data = client.put(key=sk, value=value)
                                    print("  => " + data)
                                elif keyType == KeyType.PRIVATE_HIDDEN_KEY:
                                    print("PrivateHiddenKey is not implemented yet")
                                else:
                                    raise Exception("Could not evaluate the key type of: " + fullKeyName)
                            elif verb == "scan":
                                regex = ""
                                if len(parts) > 1:
                                    regex = parts[1]
                                value = client.get_at_keys(regex=regex, fetch_metadata=False)
                                list_string = ', '.join(f'"{item}"' for item in value)
                                print("  => [" + list_string + "]")
                            elif verb == "delete":
                                fullKeyName = parts[1]
                                keyStringUtil = KeyStringUtil(full_key_name=fullKeyName)
                                keyType = keyStringUtil.get_key_type()
                                if keyType == KeyType.PUBLIC_KEY:
                                    pk = Keys.from_string(fullKeyName)
                                    data = client.delete(key=pk)
                                    print("  => " + data)
                                elif keyType == KeyType.SELF_KEY:
                                    sk = Keys.from_string(fullKeyName)
                                    data = client.delete(key=sk)
                                    print("  => " + data)
                                elif keyType == KeyType.SHARED_KEY:
                                    sk = SharedKey.from_string(fullKeyName)
                                    data = client.delete(key=sk)
                                    print("  => " + data)
                                elif keyType == KeyType.PRIVATE_HIDDEN_KEY:
                                    print("PrivateHiddenKey is not implemented yet")
                                else:
                                    raise Exception("Could not evaluate the key type of: " + fullKeyName)
                            else:
                                print("ERROR: command not recognized: [" + verb + "]") 
                        except Exception as e:
                            print(e)     
                    else:
                        try:
                            response = client.secondary_connection.execute_command(command, True)
                            print("  => " + str(response))
                        except Exception as e:
                            print("*** " + str(e))
            else:
                print("You must set an atSign before continuing")
        elif int(opt) == 3:
            sys.exit(0)

if __name__ == "__main__":
    main()
