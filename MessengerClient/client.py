# client app using rest api to communicate with server

import requests
import json
import hashlib
import secrets
import constants
from MessengerClient.security import ClientSecurityHandler
from menu_utils import Menu
import logging


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
        self.server_port = 80
        self.base_url = f'http://{self.server_ip}:{self.server_port}'
        self.security_service = ClientSecurityHandler()

        self.menu = Menu(self)

        logging.basicConfig(filename='client.log', level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s %(name)s %(message)s')
        self.logger = logging.getLogger(__name__)

    def run(self):
        self.menu.show()

    def send_message(self, url, message):  # todo: encrypt message
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        self.logger.debug(f'Sending message to {url} and message {message}')
        response = self.security_service.post(url, data=message, headers=headers)
        self.logger.debug(f'Received response {response.content}')
        return response

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
            return True
        else:
            return False

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
            return True
        else:
            return False
        
    def logout(self):
        response = self.send_message(self.base_url + constants.LOGOUT, {})
        if response.status_code == 200:
            self.token = None
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
        response = self.send_message(self.base_url + constants.SEND_GROUP_MESSAGE, {
            "group": group,
            "message": message,
        })
        if response.status_code == 200:
            return True
        else:
            return False
        
    def view_online_users(self):
        response = self.send_message(self.base_url + constants.VIEW_ONLINE_USERS, {})
        if response.status_code == 200:
            users = response.json()
            return users
        else:
            return None
        
    def show_chats(self):
        pass # todo: get chats from local
        
    def view_chat(self, user):
        pass # todo: get chat history from local

    def create_group(self, name):
        response = self.send_message(self.base_url + constants.CREATE_GROUP, {
            "name": name,
        })
        if response.status_code == 201:
            return True
        else:
            return False

    def show_group_chats(self):
        response = self.send_message(self.base_url + constants.SHOW_GROUP_CHATS, {})
        if response.status_code == 200:
            groups = response.json()
            groups_data = []
            for group in groups:
                group_last_message = '' # todo: get last message from local
                groups_data.append({'name': group['name'], 'id': group['id'], 'last_message': group_last_message})
            return groups_data
        else:
            return None

    def view_group_chat(self, group):
        pass # todo: get group chat history from local

    def add_member_to_group(self, group, user):
        response = self.send_message(self.base_url + constants.ADD_MEMBER_TO_GROUP, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True
        else:
            return False
        
    def remove_member_from_group(self, group, user):
        response = self.send_message(self.base_url + constants.REMOVE_MEMBER_FROM_GROUP, {
            "group": group,
            "user": user,
        })
        if response.status_code == 200:
            return True
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
