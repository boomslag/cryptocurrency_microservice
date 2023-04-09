from rest_framework_api.views import  StandardAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework import permissions
from .models import Token, TokenList
from .serializers import TokenSerializer
from django.db.models.query_utils import Q
import requests
from time import sleep
from django.conf import settings
from web3 import Web3
infura_url=settings.INFURA_URL
polygon_url=settings.POLYGON_RPC
web3 = Web3(Web3.HTTPProvider(infura_url))
polygon_web3 = Web3(Web3.HTTPProvider(polygon_url))
ETHERSCAN_API_KEY=settings.ETHERSCAN_API_KEY
POLYGONSCAN_API_KEY=settings.POLYGONSCAN_API_KEY
DEBUG=settings.DEBUG
import jwt
from django.conf import settings
secret_key = settings.SECRET_KEY
import rsa
import tempfile
import os
import base64
import json
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def get_polygon_contract_abi(address):
    if DEBUG:
        url = f'https://api-testnet.polygonscan.com/api?module=contract&action=getabi&address={address}&apikey={POLYGONSCAN_API_KEY}'
    else:
        url = f'https://api.polygonscan.com/api?module=contract&action=getabi&address={address}&apikey={POLYGONSCAN_API_KEY}'

    response = requests.get(url)
    data = response.json()
    if data['status'] == '1':
        return data['result']
    else:
        return None

def get_contract_abi(address):
    if DEBUG:
        url = f'https://api-goerli.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={ETHERSCAN_API_KEY}'
    else:
        url = f'https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={ETHERSCAN_API_KEY}'

    response = requests.get(url)
    data = response.json()

    if data['status'] == '1':
        return data['result']
    else:
        return None


def validate_token(request):
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]

    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.DecodeError:
        return Response({"error": "Token is invalid."}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception:
        return Response({"error": "An error occurred while decoding the token."}, status=status.HTTP_401_UNAUTHORIZED)

    return payload


class ListTokensView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, *args, **kwargs):
        payload = validate_token(request)
        tokenList = TokenList.objects.get(wallet=payload['address'])
        tokens = tokenList.tokens.all()

        # Get filter parameters
        name = request.query_params.getlist('name', None)
        symbol = request.query_params.getlist('symbol', None)
        address = request.query_params.getlist('address', None)
        decimals = request.query_params.getlist('decimals', None)
        search = request.query_params.get('search', None)

        if name and 'null' not in name:
            q_obj = Q()
            for n in name:
                q_obj |= Q(name=n)
            tokens = tokens.filter(q_obj)

        if symbol and 'null' not in symbol:
            q_obj = Q()
            for n in symbol:
                q_obj |= Q(symbol=n)
            tokens = tokens.filter(q_obj)

        if address and 'null' not in address:
            q_obj = Q()
            for n in address:
                q_obj |= Q(address=n)
            tokens = tokens.filter(q_obj)

        if decimals and 'null' not in decimals:
            q_obj = Q()
            for n in decimals:
                q_obj |= Q(decimals=n)
            tokens = tokens.filter(q_obj)

        if search and 'null' not in search:
            tokens = tokens.filter(
                                    Q(name__icontains=search) | 
                                    Q(symbol__icontains=search) | 
                                    Q(address__icontains=search) | 
                                    Q(decimals__icontains=search) 
                                )

        serializer = TokenSerializer(tokens, many=True)
        return self.paginate_response(request, serializer.data)
        # return self.send_response([],status=status.HTTP_200_OK)


class TokenBalancesView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        payload = validate_token(request)
        data=request.data

        tokens = data['tokens']
        balances = []
        for token in tokens:
            if token['symbol'] == 'ETH':
                # Skip token with symbol ETH
                continue
            token_address = token.get('address')
            token_symbol = token.get('symbol')
            # Get the ABI of the token contract from Etherscan
            abi = get_contract_abi(token_address)
            # Get the balance of the token using Web3
            contract = web3.eth.contract(address=token_address, abi=abi)
            
            balance_wei = contract.functions.balanceOf(payload['address']).call()
            balance_token = Web3.fromWei(balance_wei, 'ether')

            # Add the balance to the balances list
            balances.append({
                token_symbol: token_address,
                'balance': balance_token
            })
        # Get the balance of ETH using Web3
        eth_balance_wei = web3.eth.get_balance(payload['address'])
        eth_balance_token = Web3.fromWei(eth_balance_wei, 'ether')

        # Add the balance of ETH to the balances list
        balances.append({
            'ETH': '0x0000000000000000000000000000000000000000',
            'balance': eth_balance_token
        })
        return self.send_response(balances,status=status.HTTP_200_OK)


class PolygonTokenBalancesView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)

    # Define the number of requests per second you want to limit to
    REQUESTS_PER_SECOND = 5

    def post(self, request, *args, **kwargs):
        payload = validate_token(request)
        data=request.data

        tokens = data['tokens']
        balances = []

        # Define the time interval between requests
        time_interval = 1.0 / self.REQUESTS_PER_SECOND

        for token in tokens:
            token_address = token.get('address')
            token_symbol = token.get('symbol')

            if token_symbol == 'MATIC':
                # Get the balance of MATIC using Web3
                matic_balance_wei = polygon_web3.eth.get_balance(payload['polygon_address'])
                balance_token = Web3.fromWei(matic_balance_wei, 'ether')
                print(matic_balance_wei)
            else:
                # Get the ABI of the token contract from Etherscan
                abi = get_polygon_contract_abi(token_address)

                # Wait for the defined time interval before making the next request
                sleep(time_interval)

                # Get the balance of the token using Web3
                contract = polygon_web3.eth.contract(address=token_address, abi=abi)
                balance_wei = contract.functions.balanceOf(payload['polygon_address']).call()
                balance_token = Web3.fromWei(balance_wei, 'ether')

            # Add the balance to the balances list
            balances.append({
                token_symbol: token_address,
                'balance': balance_token
            })

        return self.send_response(balances, status=status.HTTP_200_OK)


class SendTokensView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        data=request.data
        payload = validate_token(request)
        
        # 1) Get token ABI and Contract
        token_symbol = data['token']['symbol']
        if(token_symbol!='ETH'):
            tokenAddress = data['token']['address']
            abi = get_contract_abi(tokenAddress)
            contract = web3.eth.contract(address=tokenAddress, abi=abi)

        # 2) Decrypt private Key
        wallet_request = requests.get('http://host.docker.internal:8000/api/wallets/get/?address='+payload['address']).json()
        base64_encoded_private_key_string  = wallet_request['results']['private_key']

        rsa_private_key_string = requests.get('http://host.docker.internal:8019/api/crypto/key/').json()
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            # Write the contents of rsa_private_key_string to the file
            temp_file.write(rsa_private_key_string)
        # Load the private key from the temporary file
        with open(temp_file.name, "rb") as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read())
        # Decode the Base64-encoded string
        decoded_bytes = base64.b64decode(base64_encoded_private_key_string)
        # Decrypt the bytes using the private key
        decrypted_bytes = rsa.decrypt(decoded_bytes, privkey)
        # Convert the decrypted bytes to a string
        wallet_private_key = decrypted_bytes.decode('ascii')
        # 3) Get correct Amount to send in Ether
        amount = data['amount']
        # 4) Get gas Fee
        req = requests.get('https://ethgasstation.info/json/ethgasAPI.json')
        t = json.loads(req.content)
        gas_fee=t[data['speed']]
        # 5) Sign transaction
        user_address = payload['address']
        to_address  = data['toAccount']
        nonce = web3.eth.getTransactionCount(user_address)
        if token_symbol != 'ETH':
            # If the token is not ETH, we need to use the transfer function of the token contract
            transaction = contract.functions.transfer(
                to_address, web3.toWei(amount, 'ether')).buildTransaction({
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': web3.toWei(gas_fee, 'gwei')
                })
        if token_symbol == 'ETH':
            # If the token is ETH, we can use a simple transaction to send the amount
            transaction = {
                'nonce': nonce,
                'to': to_address,
                'value': web3.toWei(amount, 'ether'),
                'gas': 21000,
                'gasPrice': web3.toWei(gas_fee, 'gwei'),
            }

        signed_tx = web3.eth.account.sign_transaction(transaction, wallet_private_key)
        try:
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            
            channel_layer = get_channel_layer()
            room_group_name = f"send_tokens_{payload['address']}"
            async_to_sync(channel_layer.group_send)(
                room_group_name,
                {
                    "type": "send_message",
                    "message": {"tx_hash": web3.toHex(tx_hash)},
                },
            )
            # Wait for the transaction receipt, with a timeout of 120 seconds
            receipt = web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
            # print(receipt)

        except ValueError as e:
            if 'already known' in str(e):
                tx_hash = signed_tx.hash
                room_group_name = f"send_tokens_{payload['address']}"
                async_to_sync(channel_layer.group_send)(
                    room_group_name,
                    {
                        "type": "send_message",
                        "message": {"tx_hash": web3.toHex(tx_hash)},
                    },
                )
            else:
                raise e

        os.unlink(temp_file.name)

        return self.send_response(web3.toHex(tx_hash), status=status.HTTP_200_OK)


class SendTokensPolygonView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        data=request.data
        payload = validate_token(request)
        
        # 1) Get token ABI and Contract
        token_symbol = data['token']['symbol']
        if(token_symbol!='MATIC'):
            tokenAddress = data['token']['address']
            abi = get_polygon_contract_abi(tokenAddress)
            contract = polygon_web3.eth.contract(address=tokenAddress, abi=abi)

        # 2) Decrypt private Key
        wallet_request = requests.get('http://host.docker.internal:8000/api/wallets/get/?address='+payload['address']).json()
        base64_encoded_private_key_string  = wallet_request['results']['polygon_private_key']

        rsa_private_key_string = requests.get('http://host.docker.internal:8019/api/crypto/key/').json()
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            # Write the contents of rsa_private_key_string to the file
            temp_file.write(rsa_private_key_string)
        # Load the private key from the temporary file
        with open(temp_file.name, "rb") as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read())
        # Decode the Base64-encoded string
        decoded_bytes = base64.b64decode(base64_encoded_private_key_string)
        # Decrypt the bytes using the private key
        decrypted_bytes = rsa.decrypt(decoded_bytes, privkey)
        # Convert the decrypted bytes to a string
        wallet_private_key = decrypted_bytes.decode('ascii')

        # 3) Get correct Amount to send in Ether
        amount = data['amount']

        # 4) Get gas Fee
        req = requests.get('https://ethgasstation.info/json/ethgasAPI.json')
        t = json.loads(req.content)
        gas_fee=t[data['speed']]

        # 5) Sign transaction
        user_address = payload['polygon_address']
        to_address  = data['toAccount']
        nonce = polygon_web3.eth.getTransactionCount(user_address)

        if token_symbol == 'MATIC':
            balance = polygon_web3.eth.getBalance(user_address)
        else:
            balance = contract.functions.balanceOf(user_address).call()
        print(f"User's balance: {balance}")

        if token_symbol != 'MATIC':
            # If the token is not ETH, we need to use the transfer function of the token contract
            transaction = contract.functions.transfer(
                to_address, polygon_web3.toWei(amount, 'ether')).buildTransaction({
                    'chainId': 80001,  # Add this line
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': polygon_web3.toWei(gas_fee, 'gwei')
                })
        if token_symbol == 'MATIC':
            # If the token is ETH, we can use a simple transaction to send the amount
            transaction = {
                'chainId': 80001,  # Add this line
                'nonce': nonce,
                'to': to_address,
                'value': polygon_web3.toWei(amount, 'ether'),
                'gas': 21000,
                'gasPrice': polygon_web3.toWei(gas_fee, 'gwei'),
            }

        signed_tx = polygon_web3.eth.account.sign_transaction(transaction, wallet_private_key)
        try:
            tx_hash = polygon_web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            
            channel_layer = get_channel_layer()
            room_group_name = f"send_tokens_{payload['address']}"
            async_to_sync(channel_layer.group_send)(
                room_group_name,
                {
                    "type": "send_message",
                    "message": {"tx_hash": polygon_web3.toHex(tx_hash)},
                },
            )
            # Wait for the transaction receipt, with a timeout of 120 seconds
            receipt = polygon_web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
            # print(receipt)
        except ValueError as e:
            if 'already known' in str(e):
                tx_hash = signed_tx.hash
                channel_layer = get_channel_layer()
                room_group_name = f"send_tokens_{payload['address']}"
                async_to_sync(channel_layer.group_send)(
                    room_group_name,
                    {
                        "type": "send_message",
                        "message": {"tx_hash": polygon_web3.toHex(tx_hash)},
                    },
                )
            else:
                raise e

        os.unlink(temp_file.name)
        return self.send_response(polygon_web3.toHex(tx_hash),status=status.HTTP_200_OK)



class AddTokenToList(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def put(self, request, *args, **kwargs):
        data=request.data
        payload = validate_token(request)
        tokenList=TokenList.objects.get(wallet=payload['address'])
        
        token, created = Token.objects.get_or_create(
            name=data['name'],
            symbol=data['symbol'],
            address=data['address'],
            network=data['network'],
            defaults={
                'decimals': data['decimals']
            }
        )

        tokenList.tokens.add(token)
        if created:
            return self.send_response('Token created and added successfully',status=status.HTTP_201_CREATED)
        else:
            return self.send_response('Token added successfully',status=status.HTTP_200_OK)