import os

from django.core.asgi import get_asgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

from channels.routing import ProtocolTypeRouter

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter


# from middleware.authmiddleware import JWTAuthMiddlewareStack
import apps.tokens.routing as SendTokensRouting
import apps.courses.routing as DeployNFTRouting

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': AuthMiddlewareStack(
        URLRouter(
            SendTokensRouting.websocket_urlpatterns + DeployNFTRouting.websocket_urlpatterns
        )
    ),
})
