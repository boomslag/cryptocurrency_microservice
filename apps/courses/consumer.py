import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import *
from django.core.exceptions import ObjectDoesNotExist
import jwt
from django.conf import settings
secret_key = settings.SECRET_KEY

class DeployNFTConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        # Get UserID
        self.room_name = self.scope["url_route"]["kwargs"]["room_name"]
        self.room_group_name = "deploy_nft_%s" % self.room_name

        # Join room group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message_type = text_data_json['type']
        message = text_data_json["message"]
        event = {
            'type': 'send_message',
            'message': message
        }
        # send message to group
        await self.channel_layer.group_send(self.group_name, event)
    
    async def send_message(self, event):
        message = event['message']
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'send_message',
            'message': message
        }))