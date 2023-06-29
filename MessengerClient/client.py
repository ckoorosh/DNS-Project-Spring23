# client app using rest api to communicate with server

import requests
import json
import hashlib
import secrets
import constants
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
        response = requests.post(url, data=message, headers=headers)
        self.logger.debug(f'Received response {response.json()}')
        return response

    def encrypt_message(self, message):
        return message.encode()

    def decrypt_message(self, message):
        return message.decode()

    def register(self, username, password):
        self.username = username
        self.password = password
        # todo: generate public/private key pair
        self.public_key = secrets.token_urlsafe(16)
        response = self.send_message(self.base_url + constants.REGISTER, {
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


if __name__ == '__main__':
    client = Client()
    client.run()
