import json
import os

from channels.generic.websocket import AsyncWebsocketConsumer

from MessangerServer.utlis import JwtUtil, Singleton
from MessangerServer.websocket_manager import WebsocketManager

cookie_name = os.getenv('WS_AUTH_COOKIE_NAME')


class WSConsumer(AsyncWebsocketConsumer):
    user_id: str
    token: str

    async def connect(self):
        token = self.scope['cookies'][cookie_name]
        user_id = self.scope['url_route']['kwargs']['user_id']
        decoded_token = JwtUtil().jwt_decode(token)
        if decoded_token['user_id'] != user_id:
            raise Exception('Unauthorized user')
        self.user_id = user_id
        self.token = token
        await self.channel_layer.group_add(self.user_id, self.channel_name)
        await self.accept()
        WebsocketManager().add_group(user_id)

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.user_id, self.channel_name)
        WebsocketManager().remove_group(self.user_id)

    async def receive(self, text_data=None, bytes_data=None, **kwargs):
        await self.disconnect(close_code=111)
        pass

    async def send_message(self, message):
        await self.send(text_data=json.dumps({'message': message['message']}))
