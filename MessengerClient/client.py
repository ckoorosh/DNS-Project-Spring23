# client app using rest api to communicate with server
import json
import logging
import threading
import os
import glob

import websocket
from dotenv import load_dotenv

import constants
from UserKeys import UserKeys
from menu_utils import Menu
from security import ClientSecurityHandler


class Client:
    def __init__(self):
        load_dotenv()
        self.token = None
        self.username = None
        self.password = None
        self.public_key = None  # load public key from file if exists
        self.private_key = None
        self.user_keys = UserKeys()

        self.server_ip = os.getenv('SERVER_IP')
        self.server_port = int(os.getenv('SERVER_PORT'))
        self.base_url = f'http://{self.server_ip}:{self.server_port}'
        self.ws_url = f'ws://{self.server_ip}:{self.server_port}/ws'
        self.security_service = ClientSecurityHandler()

        self.menu = Menu(self)

        logging.basicConfig(filename='client.log', level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

        if not os.path.exists('chats'):
            os.makedirs('chats')

    def run(self):
        self.menu.show()

    def send_message(self, url, message):  # todo: encrypt message
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        self.logger.debug(f'Sending message to {url} and message {message}')
        content, response = self.security_service.post(url, data=message, headers=headers)
        self.logger.debug(f'Received content {content} and response {response.text}')
        return content, response

    def on_message(self, ws, message):
        if type(message) == bytes:
            return
        data = json.loads(message)
        if 'type' in data and data['type'] == 'ping':
            ws.send(json.dumps({'type': 'pong'}))
            return

        if data.__contains__('byte_cipher'):
            raise NotImplementedError()

        plain = self.security_service.decrypt_str(data['nonce'], data['cipher'])
        message_dict = json.loads(plain)
        real_message: str = message_dict['message']['message']
        if real_message.startswith('1'):
            self.security_service.answer_exchange_key(real_message[1:], self.username)
        elif real_message.startswith('2'):
            self.security_service.receive_message(real_message[1:])
        ws.send(json.dumps({'type': 'pong'}))
        # self.logger.info(f'Received WS message {message_dict}')

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
        content, response = self.send_message(self.base_url + constants.REGISTER, {
            "name": self.name,
            "username": self.username,
            "password": self.password
        })

        if response.status_code == 201:
            self.token = json.loads(content)['token']
            self.connect_ws()
            self.user_keys.generate()
            keys = self.user_keys.get_public_keys()
            content, response = self.send_message(self.base_url + constants.SEND_PUBLIC_KEYS, {
                'idk': keys.idk,
                'signed_prekey': keys.signed_prekey,
                'prekey_signature': keys.prekey_signature,
                'ot_prekeys': keys.ot_prekeys
            })
            self.user_keys.save_keys(self.password)
            if response.status_code == 200:
                return True
        else:
            return False

    def connect_ws(self):
        nonce, token = self.security_service.encrypt_str(self.token)
        session_id = self.security_service.session_id
        self.ws = websocket.WebSocketApp(f'{self.ws_url}/{self.username}/',
                                         cookie=f'authCookie={token};nonce={nonce};session={session_id}',
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
        content, response = self.send_message(self.base_url + constants.LOGIN, {
            "username": self.username,
            "password": self.password
        })

        if response.status_code == 200:
            self.token = json.loads(content)['token']
            self.connect_ws()
            self.user_keys.load_keys(self.password)
            return True
        else:
            return False

    def logout(self):
        content, response = self.send_message(self.base_url + constants.LOGOUT, {})
        if response.status_code == 200:
            self.token = None
            self.ws.close()
            return True
        else:
            return False

    def send_chat_message(self, recipient, message):
        content, response = self.send_message(self.base_url + constants.SEND_CHAT_MESSAGE, {
            "recipient": recipient,
            "message": message,
        })
        if response.status_code == 200:
            return True
        else:
            return False

    def send_group_chat_message(self, group, message):
        content, response = self.send_message(self.base_url + constants.SEND_GROUP_MESSAGE, {
            "group": group,
            "message": message,
        })
        if response.status_code == 200:
            return True
        else:
            return False

    def view_online_users(self):
        content, response = self.send_message(
            self.base_url + constants.VIEW_ONLINE_USERS, {})
        if response.status_code == 200:
            users = json.loads(content)
            return users
        else:
            return None

    def show_chats(self):
        chats = []
        for file in glob.glob("chats/*.json"):
            chats.append(file.split('\\')[1].split('.')[0])
        return chats

    def view_chat(self, user):
        chats = self.show_chats()
        if user in chats:
            messages = self.security_service.load_chat(user, self.password)
            return True, messages
        else:
            return False, None
    
    def save_chat(self, user, messages):
        self.security_service.save_chat(user, self.password, messages)

    def create_group(self, name):
        content, response = self.send_message(self.base_url + constants.CREATE_GROUP, {
            "name": name,
        })
        if response.status_code == 201:
            return True
        else:
            return False

    def show_group_chats(self):
        content, response = self.send_message(
            self.base_url + constants.SHOW_GROUP_CHATS, {})
        if response.status_code == 200:
            groups = json.loads(content)
            groups_data = []
            for group in groups:
                group_last_message = ''  # todo: get last message from local
                groups_data.append({'name': group['name'],
                                    'id': group['id'],
                                    'last_message': group_last_message})
            return groups_data
        else:
            return None

    def view_group_chat(self, group):
        pass  # todo: get group chat history from local

    def add_member_to_group(self, group, user):
        content, response = self.send_message(self.base_url + constants.ADD_MEMBER_TO_GROUP, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True
        else:
            return False

    def remove_member_from_group(self, group, user):
        content, response = self.send_message(self.base_url + constants.REMOVE_MEMBER_FROM_GROUP, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True
        else:
            return False

    def make_member_admin(self, group, user):
        content, response = self.send_message(self.base_url + constants.MAKE_MEMBER_ADMIN, {
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
