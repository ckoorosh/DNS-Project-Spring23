import asyncio
import json
import os

from channels.generic.websocket import AsyncWebsocketConsumer

from MessangerServer.utlis import JwtUtil
from MessangerServer.websocket_manager import WebsocketManager

cookie_name = os.getenv('WS_AUTH_COOKIE_NAME')


class WSConsumer(AsyncWebsocketConsumer):
    user_id: str
    token: str
    ping_interval: int = 10
    connected: bool

    async def connect(self):
        token = self.scope['cookies'][cookie_name]
        user_id = self.scope['url_route']['kwargs']['username']
        decoded_token = JwtUtil().jwt_decode(token)
        if decoded_token['username'] != user_id:
            raise Exception('Unauthorized user')
        self.user_id = user_id
        self.token = token
        await self.channel_layer.group_add(self.user_id, self.channel_name)
        await self.accept()
        WebsocketManager().add_group(user_id)
        self.connected = True
        asyncio.create_task(self.schedule_ping())

    async def disconnect(self, close_code):
        self.connected = False
        await self.channel_layer.group_discard(self.user_id, self.channel_name)
        WebsocketManager().remove_group(self.user_id)

    async def receive(self, text_data=None, bytes_data=None, **kwargs):
        pass

    async def send_message(self, message):
        to_send = {
            'type': 'message',
            'message': message
        }
        await self.send(text_data=json.dumps(to_send))

    async def send_bytes(self, bytes_data):
        await self.send(bytes_data=bytes_data)

    async def schedule_ping(self):
        while True:
            await asyncio.sleep(self.ping_interval)
            if self.connected:
                await self.send(text_data=json.dumps({'type': 'ping'}))
            else:
                break
