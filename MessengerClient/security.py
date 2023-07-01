import requests

from MessangerServer.utlis import Singleton


class ClientSecurityHandler(metaclass=Singleton):
    def __init__(self):
        self.session = requests.Session()
        pass

    def post(self, url, data=None, headers=None):
        return self.session.post(url, data=data, headers=headers)
