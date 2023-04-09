import json, os, django
from confluent_kafka import Consumer
import uuid
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from django.conf import settings
debug = settings.DEBUG
pdm_goerli = settings.PDM_ADDRESS_GOERLI
pdm_mainnet = settings.PDM_ADDRESS_MAINNET

galr_goerli = settings.GALR_ADDRESS_GOERLI
galr_mainnet = settings.GALR_ADDRESS_MAINNET

from django.apps import apps

TokenList = apps.get_model('tokens', 'TokenList')
NFTList = apps.get_model('tokens', 'NFTList')
Token = apps.get_model('tokens', 'Token')
NFT = apps.get_model('tokens', 'NFT')

class UUIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            # if obj is uuid, we simply return the value of uuid
            return str(obj)
        return json.JSONEncoder.default(self, obj)

consumer1 = Consumer({
    'bootstrap.servers': os.environ.get('KAFKA_BOOTSTRAP_SERVER'),
    'security.protocol': os.environ.get('KAFKA_SECURITY_PROTOCOL'),
    'sasl.username': os.environ.get('KAFKA_USERNAME'),
    'sasl.password': os.environ.get('KAFKA_PASSWORD'),
    'sasl.mechanism': 'PLAIN',
    'group.id': os.environ.get('KAFKA_GROUP'),
    'auto.offset.reset': 'earliest'
})
consumer1.subscribe([os.environ.get('KAFKA_TOPIC')])

consumer2 = Consumer({
    'bootstrap.servers': os.environ.get('KAFKA_BOOTSTRAP_SERVER'),
    'security.protocol': os.environ.get('KAFKA_SECURITY_PROTOCOL'),
    'sasl.username': os.environ.get('KAFKA_USERNAME'),
    'sasl.password': os.environ.get('KAFKA_PASSWORD'),
    'sasl.mechanism': 'PLAIN',
    'group.id': os.environ.get('KAFKA_GROUP_2'),
    'auto.offset.reset': 'earliest'
})
consumer2.subscribe([os.environ.get('KAFKA_TOPIC_2')])

while True:
    msg1 = consumer1.poll(1.0)
    msg2 = consumer2.poll(1.0)

    if msg1 is not None and not msg1.error():
        topic1 = msg1.topic()
        value1 = msg1.value()

        if topic1 == 'wallet_created':
            if msg1.key() == b'create_wallet':
                wallet_data = json.loads(value1)
                wallet_address = wallet_data['address']
                # check if tokenList exists for the given wallet address
                tokenList, created = TokenList.objects.get_or_create(wallet=wallet_address)
                if created:
                    # Add the predefined tokens
                    predefined_tokens = [
                        {'name': 'Praedium', 'symbol': 'PDM', 'address': pdm_goerli if settings.DEBUG else pdm_mainnet, 'decimals':18, 'network': 'Polygon'},
                        {'name': 'Galerium', 'symbol': 'GALR', 'address': galr_goerli if settings.DEBUG else galr_mainnet, 'decimals':18, 'network': 'Polygon'},
                        {'name': 'Ethereum', 'symbol': 'ETH', 'address': '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 'decimals':18, 'network': 'Ethereum'},
                        {'name': 'Matic', 'symbol': 'MATIC', 'address': '0x0000000000000000000000000000000000001010', 'decimals':18, 'network': 'Polygon'}
                    ]
                    for token_data in predefined_tokens:
                        token, created = Token.objects.get_or_create(**token_data)
                        tokenList.tokens.add(token)
                    tokenList.save()
                nftList, created = NFTList.objects.get_or_create(wallet=wallet_address)

    if msg2 is not None and not msg2.error():
        topic2 = msg2.topic()
        value2 = msg2.value()

        if topic2 == 'nft_minted':
            if msg2.key() == b'create_and_add_nft_to_nftList':
                data = json.loads(value2)
                wallet_address = data['wallet_address']

                nft = NFT.objects.create(
                    nft_id=data['nft_id'],
                    ticket_id=data['ticket_id'],
                    ticket_address=data['ticket_address'],
                    transaction_hash=data['transaction_hash'],
                )
                nft_list, created = NFTList.objects.get_or_create(wallet=wallet_address)
                nft_list.nfts.add(nft)
                nft_list.save()

consumer1.close()
consumer2.close()