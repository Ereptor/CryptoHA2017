from message import Message
import base64
from time import sleep
from threading import Thread
import urllib2
import json
import random
from Crypto.Protocol import KDF
import os.path

import diffie
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from config import *

from Crypto.Cipher import AES
from Crypto import Random


class Conversation:
    '''
    Represents a conversation between participants
    '''

    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager  # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        )  # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True

        self.ratchet_keys = {}  # CRYPTO
        self.my_ratchet_keys = {}
        self.session_keys = {}  # CRYPTO
        self.root_keys = {}  # CRYPTO
        self.chain_keys = {}  # CRYPTO
        self.msg_keys = {}

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)

    def setup_conversation(self, identity_secret, signed_secret, cookie):
        '''
        Prepares the conversation for usage
        :return:
        '''
        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # Since there is no crypto in the current version, no preparation is needed, so do nothing
        # replace this with anything needed for your key exchange

        for participant in self.manager.get_other_users():
            # Get keys for participants in loop until right signature is returned:
            while True:
                req = urllib2.Request("http://" + SERVER + ":" + SERVER_PORT + "/getKeys/" + participant)
                req.add_header("Cookie", cookie)
                r = urllib2.urlopen(req)
                string = r.read()

                keys = json.loads(string)
                keyhash = SHA.new(keys["signed_prekey"] + keys["identity_key"])
                publicKey = RSA.importKey(open("public.pem").read())
                verifier = pkcs.new(publicKey)
                if (verifier.verify(keyhash, base64.b64decode(keys["signature"]))):
                    break
                else:
                    print "Possibly faked keys returned for user " + participant + ", retrying..."

            diffie1 = diffie.derive_shared_secret(identity_secret,
                                                  int(keys["signed_prekey"]))

            diffie2 = diffie.derive_shared_secret(signed_secret,
                                                  int(keys["identity_key"]))

            if self.id in self.manager.self_made_conversation:
                self.session_keys[participant] = str(diffie1) + str(diffie2)
            else:
                self.session_keys[participant] = str(diffie2) + str(diffie1)

            print participant + " : " + self.session_keys[participant]

        conversationkey_path = "conversationkeys_" + str(self.id) + ".json"
        if not os.path.exists(conversationkey_path):
            self.update_my_ratchet_key(diffie.generate_keys(), 0)
        else:
            with open(conversationkey_path, "r") as con_keys:
                self.my_ratchet_keys = json.load(con_keys)

        counterconversation_path = "counterconversation_" + str(self.id) + ".json"
        if not os.path.exists(counterconversation_path):
            with open("counterconversation_" + str(self.id) + ".json", "w") as counter_file:
                counter_dict={"sent": 0, "received": 0}
                json.dump(counter_dict, counter_file)

    def setup_pairwaise(self, part_a, part_b, sender_key):

        return

    def setup_group_conversation(self):

        participants = self.manager.get_other_users()

        sender_key = 0

        for participant in participants:
            if participant != self.manager.user_name:
                self.setup_pairwaise(self.manager.user_name, participant, sender_key)

        return

    def update_last_ratchet_key(self, user_name, key):
        """ Update ratchet key list with last seen key for user """
        self.ratchet_keys[user_name] = key

    def update_my_ratchet_key(self, key, m_id):
        """
        key = {"public": x, "private": y}
        m_id: ratchet key is valid from this message
        """
        self.my_ratchet_keys[m_id] = key
        with open("conversationkeys_" + str(self.id) + ".json", "w") as keys_file:
            json.dump(self.my_ratchet_keys, keys_file)

    def get_my_ratchet_key_for_id(self, m_id):
        if m_id < 0:
            return None
        keys = sorted(self.my_ratchet_keys.keys())
        for i in range(0, len(keys)):
            if m_id < keys[i]:
                return self.my_ratchet_keys[keys[i - 1]]
        return self.my_ratchet_keys[keys[-1]]

    def get_last_ratchet_key(self, user_name):
        """ Return last ratchet key seen for user (None if it's the first) """
        if not user_name in self.ratchet_keys:
            return None
        return self.ratchet_keys[user_name]

    def get_keys_to_symmetric_ratchet(self, key):
        """Use this function to get root key and chain key0 from session key or to get new chain key and message key from old chain key"""

        kdf = KDF.PBKDF2(key, "saltsalt", 32)
        key1 = kdf[:16]
        key2 = kdf[16:]
        return key1, key2

    def get_keys_to_asymmetric_ratchet(self, key1, key2):
        """Use this function to get a temporary key and chain key or new root key and a new sender chain key"""
        kdf = KDF.PBKDF2(key1, key2, 32)
        new_key1 = kdf[:16]
        new_key2 = kdf[16:]
        return new_key1, new_key2

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        if self.manager.user_name != owner_str:
            # process message here
            # example is base64 decoding, extend this with any crypto processing of your protocol
            decoded_msg = base64.decodestring(msg_raw)

            raw_msg = decoded_msg.split("|")

            other_pik = raw_msg[0]
            other_pspk = raw_msg[1]
            counter = raw_msg[2]
            e_msg = raw_msg[3]
            iv = e_msg[:16]
            secret_msg = e_msg[16:]

            self.msg_keys[owner_str], self.chain_keys[owner_str] = self.get_keys_to_symmetric_ratchet(
                self.session_keys[owner_str])

            print  "msg: " + self.msg_keys[owner_str]
            print  "chain: " + self.chain_keys[owner_str]

            cipher = AES.new(self.msg_keys[owner_str], AES.MODE_CFB, iv)
            msg = cipher.decrypt(secret_msg)

            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=msg,
                owner_str=owner_str
            )

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''

        participants = self.manager.get_other_users()

        self.msg_keys[participants[0]], self.chain_keys[participants[0]] = self.get_keys_to_symmetric_ratchet(
            self.session_keys[participants[0]])

        print  "msg: " + self.msg_keys[participants[0]]
        print  "chain: " + self.chain_keys[participants[0]]

        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.msg_keys[participants[0]], AES.MODE_CFB, iv)

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if originates_from_console == True:
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )

            self.printed_messages.append(m)

        e_msg = iv + cipher.encrypt(msg_raw)

        msg = str(self.manager.identity_key["public"]) + "|" + str(self.manager.signed_prekey["public"]) + "|" + str(
            0) + "|" + e_msg

        encoded_msg = base64.encodestring(msg)

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)

    def increase_sent_counter(self):
        with open("counterconversation_" + str(self.id) + ".json", "r+") as counter_file:
            count_dict = json.load(counter_file)
            count_dict["sent"] += 1
            json.dump(count_dict, counter_file)

    def increase_received_counter(self):
        with open("counterconversation_" + str(self.id) + ".json", "r+") as counter_file:
            count_dict = json.load(counter_file)
            count_dict["received"] += 1
            json.dump(count_dict, counter_file)

    def get_sent_counter(self):
        with open("counterconversation_" + str(self.id) + ".json", "r") as counter_file:
            return json.load(counter_file)["sent"]


    def get_received_counter(self):
        with open("counterconversation_" + str(self.id) + ".json", "r") as counter_file:
            return json.load(counter_file)["received"]