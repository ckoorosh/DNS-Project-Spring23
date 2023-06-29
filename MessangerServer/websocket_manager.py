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
        return self.groups
    
    def is_user_online(self, user_id):
        return str(user_id) in self.groups

    async def send_message_to_user(self, user_id, message):
        if str(user_id) not in self.groups:
            return False

        channel_layer = get_channel_layer()

        await channel_layer.group_send(
            str(user_id),
            {
                'type': 'send_message',
                'message': message,
            }
        )
        return True
