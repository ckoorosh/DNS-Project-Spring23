# client app using rest api to communicate with server

import requests
import secrets
import constants
from menu_utils import Menu
import logging
import websocket
import json
import threading
from SecurityUtils import *
import os
import pickle
import base64


def b64_to_bytes(string: str) -> bytes:
    return base64.b64decode(string)


def bytes_to_b64(bytes_data: bytes) -> str:
    return base64.b64encode(bytes_data).decode('utf-8')


def cipher_pub(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


class Client:
    def __init__(self):
        self.token = None
        self.username = None
        self.password = None
        self.public_key = None  # load public key from file if exists
        self.private_key = None
        self.server_nonce = None
        self.client_nonce = None
        self.server_ip = '127.0.0.1'
        self.server_port = 8000
        self.base_url = f'http://{self.server_ip}:{self.server_port}'
        self.ws_url = f'ws://{self.server_ip}:{self.server_port}/ws'
        self.menu = Menu(self)

        # group
        self.group_chat_history = dict()  # saved in group_chat.txt
        self.keys = dict()  # saved in keys.txt
        self.temp_dh_key = b''
        self.temp_iv = b''
        logging.basicConfig(filename='client.log', level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

    def add_to_keys(self, dict_key, dict_value):
        self.keys[dict_key] = dict_value
        # new_iv = create_aes_iv()
        # key_file = open('keys.txt', 'wb')
        # key = hash_sha256(self.password)[:32]
        # coded_keys = self.keys ####
        # key_file.write(new_iv + encrypt_aes(key, new_iv, new_iv + coded_keys))
        # key_file.close()
        # print(self.keys)

    def add_to_group_chat_history(self):
        pass

    # TODO: write in file and add to dict

    def load_keys(self):
        # if not os.path.exists('keys.txt'):
        #    return
        # key_file = open('keys.txt', 'rb')
        # file_content = key_file.read()
        # iv = file_content[:16]
        # keys_ciphered = file_content[16:]
        # decrypted = decrypt_aes(hash_sha256(self.password)[:32], iv, keys_ciphered)
        # self.keys = decrypted ####
        # key_file.close()
        pass

    def load_group_messages(self):
        pass

    def run(self):
        self.menu.show()

    def send_message(self, url, message):  # todo: encrypt message
        # message = enc(message)
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        self.logger.debug(f'Sending message to {url} and message {message}')
        response = requests.post(url, data=message, headers=headers)
        self.logger.debug(f'Received response {response.text}')
        return response

    def handshake1_handle(self, ws, message):
        if 'type' in message and message['type'] == 'group handshake 1':
            # print('first hand', message)
            user = message['sender']
            group = message['group']
            public_key = serialization.load_pem_public_key(b64_to_bytes(message['value']))
            params = serialization.load_pem_parameters(b64_to_bytes(message['params']))
            private_dh = create_dh_private_key(params)
            self.temp_dh_key = join_dh_keys(private_dh, public_key)
            my_public_key = get_dh_public_key(private_dh)
            iv = create_aes_iv()
            sending_req = {
                "destination": user,
                "value": bytes_to_b64(cipher_pub(my_public_key)),
                'iv': bytes_to_b64(iv),
                "params": 'params',
                "group": group,
                "type": 'group handshake 2',
            }
            response_2 = self.send_message(self.base_url + constants.GROUP_HANDSHAKE, sending_req)
        else:
            return

    def handshake2_handle(self, ws, message):
        if 'type' in message and message['type'] == 'group handshake 2':
            print('second hand', message)
            user = message['sender']
            group = message['group']
            public_key = serialization.load_pem_public_key(b64_to_bytes(message['value']))
            iv = b64_to_bytes(message['iv'])
            self.temp_dh_key = join_dh_keys(self.temp_dh_key, public_key)
            enciphered = encrypt_aes(self.keys[group], iv, self.keys[group])
            sending_req = {
                "destination": user,
                "value": base64.b64encode(enciphered).decode('latin-1'),
                "params": 'params',
                "group": group,
                'iv': 'iv',
                "type": 'group handshake 3'
            }
            response_2 = self.send_message(self.base_url + constants.GROUP_HANDSHAKE, sending_req)

    def handshake3_handle(self, ws, message):
        if 'type' in message and message['type'] == 'group handshake 3':
            print(message)
            g_key = base64.b64decode(message['value'])
            g_key = decrypt_aes(self.temp_dh_key, self.temp_iv, g_key)
            print('key', g_key)

    def on_message(self, ws, message):
        if type(message) == bytes:
            return
        data = json.loads(message)
        if 'type' in data and data['type'] == 'ping':
            ws.send(json.dumps({'type': 'pong'}))
        else:
            self.logger.info(f'Received WS message {message}')

        self.handshake1_handle(ws, data['message']['message'])
        self.handshake2_handle(ws, data['message']['message'])
        self.handshake3_handle(ws, data['message']['message'])

    def on_error(self, ws, error):
        self.logger.error(error)

    def on_close(self, ws):
        self.logger.info("WebSocket closed")

    def on_open(self, ws):
        self.logger.info("WebSocket opened")

    def encrypt_message(self, message):
        return message.encode()

    def decrypt_message(self, message):
        return message.decode()

    def register(self, name, username, password):
        self.name = name
        self.username = username
        self.password = password
        # todo: generate public/private key pair
        self.public_key = secrets.token_urlsafe(16)
        response = self.send_message(self.base_url + constants.REGISTER, {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "public_key": self.public_key,
        })

        if response.status_code == 201:
            self.token = response.json()['token']
            self.connect_ws()
            return True
        else:
            return False

    def connect_ws(self):
        self.ws = websocket.WebSocketApp(f'{self.ws_url}/{self.username}/',
                                         cookie=f'authCookie={self.token}',
                                         on_message=self.on_message,
                                         on_error=self.on_error,
                                         on_close=self.on_close,
                                         on_open=self.on_open)
        wst = threading.Thread(target=self.ws.run_forever)
        wst.daemon = True
        wst.start()

    def login(self, username, password):
        self.username = username
        self.password = password
        response = self.send_message(self.base_url + constants.LOGIN, {
            "username": self.username,
            "password": self.password,
            "public_key": self.public_key,
        })

        if response.status_code == 200:
            self.token = response.json()['token']
            self.connect_ws()
            return True
        else:
            return False

    def logout(self):
        response = self.send_message(self.base_url + constants.LOGOUT, {})
        if response.status_code == 200:
            self.token = None
            self.ws.close()
            return True
        else:
            return False

    def send_chat_message(self, recipient, message):
        response = self.send_message(self.base_url + constants.SEND_CHAT_MESSAGE, {
            "recipient": recipient,
            "message": message,
        })
        if response.status_code == 200:
            return True
        else:
            return False

    def send_group_chat_message(self, group, message):
        message_packet = {
            "group": group,
            "message": message,
        }
        response = self.send_message(self.base_url + constants.SEND_GROUP_MESSAGE, message)
        print('client', self.username, 'sent and recieved', response)
        if response.status_code == 200:
            return True
        else:
            return False

    def view_online_users(self):
        response = self.send_message(
            self.base_url + constants.VIEW_ONLINE_USERS, {})
        if response.status_code == 200:
            users = response.json()
            return users
        else:
            return None

    def show_chats(self):
        pass  # todo: get chats from local

    def view_chat(self, user):
        pass

    def create_group(self, name):

        response = self.send_message(self.base_url + constants.CREATE_GROUP, {
            "name": name,
        })
        if response.status_code == 200:
            print(response.json())
            values = response.json()
            group_key = create_aes_key()
            print(values)
            self.add_to_keys(values['group id'], group_key)
            return True
        else:
            return False

    def show_group_chats(self):
        response = self.send_message(
            self.base_url + constants.SHOW_GROUP_CHATS, {})
        if response.status_code == 200:
            groups = response.json()
            groups_data = []
            for group in groups:
                group_last_message = ''
                groups_data.append({'name': group['name'],
                                    'id': group['id'],
                                    'last_message': group_last_message})
            return groups_data
        else:
            return None

    def view_group_chat(self, group):
        if not group in self.group_chat_history:
            data = {'name': group,
                    'messages': []}  # list: (sender: message)
            self.group_chat_history[group] = data
        return True, self.group_chat_history[group]

    def add_member_to_group(self, group, user):
        send_message = {'group': group,
                        'user': user}
        response = self.send_message(self.base_url + constants.ADD_MEMBER_TO_GROUP, send_message)
        print(response)
        if response.status_code == 200:
            params = create_dh_params()
            private_dh = create_dh_private_key(params)
            self.temp_dh_key = private_dh
            public_key = get_dh_public_key(private_dh)
            sending_req = {
                "destination": user,
                'iv': 'iv',
                "value": bytes_to_b64(cipher_pub(public_key)),
                "params": bytes_to_b64(params.parameter_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.ParameterFormat.PKCS3)),
                "group": group,
                "type": 'group handshake 1'
            }

            response_2 = self.send_message(self.base_url + constants.GROUP_HANDSHAKE, sending_req)
            return True
        else:
            return False

    def remove_member_from_group(self, group, user):
        response = self.send_message(self.base_url + constants.REMOVE_MEMBER_FROM_GROUP, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True  # new nadshake with all members
        else:
            return False

    def make_member_admin(self, group, user):
        response = self.send_message(self.base_url + constants.MAKE_MEMBER_ADMIN, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True
        else:
            return False


if __name__ == '__main__':
    client = Client()
    client.run()
