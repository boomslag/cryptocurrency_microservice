from django.urls import re_path

from .consumer import DeployNFTConsumer

websocket_urlpatterns = [
    re_path(r'^ws/deploy_nft/(?P<room_name>[^/]+)/$', DeployNFTConsumer.as_asgi()),
]