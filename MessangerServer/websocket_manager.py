from channels.layers import get_channel_layer

from MessangerServer.utlis import Singleton


class WebsocketManager(metaclass=Singleton):
    def __init__(self):
        self.groups = set()
        pass

    def add_group(self, group_id):
        self.groups.add(group_id)

    def remove_group(self, group_id):
        self.groups.remove(group_id)

    def get_connected_user_ids(self):
        return list(self.groups)
    
    def is_user_online(self, username):
        return username in self.groups

    async def send_message_to_user(self, username, message):
        if username not in self.groups:
            return False

        channel_layer = get_channel_layer()

        await channel_layer.group_send(
            username,
            {
                'type': 'send_message',
                'message': message,
            }
        )
        return True

    async def send_bytes_to_user(self, username, bytes_data):
        if not self.is_user_online(username):
            return False
        channel_layer = get_channel_layer()

        await channel_layer.group_send(
            str(username),
            {
                'type': 'send_bytes',
                'bytes_data': bytes_data,
            }
        )
        return True
