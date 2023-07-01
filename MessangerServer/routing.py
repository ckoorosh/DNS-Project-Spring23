from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from django.urls import re_path

from MessangerServer import consumers

websocket_patterns = [
    re_path(r'ws/(?P<username>\w+)/$', consumers.WSConsumer.as_asgi())
]

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        "websocket": AuthMiddlewareStack(URLRouter(websocket_patterns)),
    }
)
