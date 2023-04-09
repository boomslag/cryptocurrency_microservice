import os

from django.core.asgi import get_asgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django_asgi_app = get_asgi_application()

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter

import apps.tokens.routing as SendTokensRouting
import apps.courses.routing as DeployNFTRouting

application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': AuthMiddlewareStack(
        URLRouter(
            SendTokensRouting.websocket_urlpatterns + DeployNFTRouting.websocket_urlpatterns
        )
    ),
})
