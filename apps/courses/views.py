import os
from rest_framework_api.views import  StandardAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework import permissions
from django.db.models.query_utils import Q
import requests
import random
from django.conf import settings
from web3 import Web3
from time import sleep
infura_url=settings.INFURA_URL
owner_wallet = settings.OWNER_WALLET
owner_wallet_key = settings.OWNER_WALLET_KEY

booth_contract = settings.BOOTH_CONTRACT
affiliates_contract = settings.AFFILIATES_CONTRACT
uridium_wallet = settings.URIDIUM_WALLET
uridium_wallet_key = settings.URIDIUM_WALLET_KEY
ticket_contract=settings.TICKET_CONTRACT
polygon_url=settings.POLYGON_RPC
web3 = Web3(Web3.HTTPProvider(infura_url))
polygon_web3 = Web3(Web3.HTTPProvider(polygon_url))
ETHERSCAN_API_KEY=settings.ETHERSCAN_API_KEY

POLYGONSCAN_API_KEY=settings.POLYGONSCAN_API_KEY
api_keys = settings.POLYGONSCAN_API_KEYS

DEBUG=settings.DEBUG
import jwt
from io import StringIO
from django.conf import settings
secret_key = settings.SECRET_KEY
auth_ms_url = settings.AUTH_MS_URL
cryptography_ms_url = settings.CRYPTOGRAPHY_MS_URL
import rsa
import tempfile
import os
import base64
from pathlib import Path
import json

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def get_contract_abi(address):
    url = f'https://api-goerli.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={ETHERSCAN_API_KEY}'
    # if DEBUG:
    # else:
    #     url = f'https://api.etherscan.io/api?module=contract&action=getabi&address={address}&apikey={ETHERSCAN_API_KEY}'

    response = requests.get(url)
    data = response.json()

    if data['status'] == '1':
        return data['result']
    else:
        return None

def get_polygon_contract_abi(address):
    url = f'https://api-testnet.polygonscan.com/api?module=contract&action=getabi&address={address}&apikey={POLYGONSCAN_API_KEY}'
    # if DEBUG:
    # else:
    #     url = f'https://api.polygonscan.com/api?module=contract&action=getabi&address={address}&apikey={POLYGONSCAN_API_KEY}'

    response = requests.get(url)
    data = response.json()
    if data['status'] == '1':
        return data['result']
    else:
        return None

def get_polygon_contract_bytecode(address):
    url = f'https://api-testnet.polygonscan.com/api?module=proxy&action=eth_getCode&address={address}&apikey={POLYGONSCAN_API_KEY}'
    # if DEBUG:
    # else:
    #     url = f'https://api.polygonscan.com/api?module=proxy&action=eth_getCode&address={address}&apikey={POLYGONSCAN_API_KEY}'

    response = requests.get(url)
    data = response.json()
    return data['result']

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

def decrypt_private_key(address):
    # Get wallet information from the backend API
    wallet_request = requests.get(f'{auth_ms_url}/api/wallets/get/?address={address}').json()
    base64_encoded_private_key_string = wallet_request['results']['private_key']
    
    # Get RSA private key from the backend API
    rsa_private_key_string = requests.get(f"{cryptography_ms_url}/api/crypto/key/").json()
    
    # Create a temporary file to store the RSA private key
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
    
    return wallet_private_key

def decrypt_polygon_private_key(address):
    # Get wallet information from the backend API
    wallet_request = requests.get(f'{auth_ms_url}/api/wallets/get/?address={address}').json()
    base64_encoded_private_key_string = wallet_request['results']['polygon_private_key']
    
    # Get RSA private key from the backend API
    rsa_private_key_string = requests.get(f"{cryptography_ms_url}/api/crypto/key/").json()
    
    # Create a temporary file to store the RSA private key
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
    
    return wallet_private_key


class GetNFTDeploymentPriceView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, *args, **kwargs):
        validate_token(request)

        user_address = request.GET.get('address', None)
        user_polygon_address = request.GET.get('polygonAddress', None)

        abi = get_polygon_contract_abi(ticket_contract)

        bytecode = get_polygon_contract_bytecode(ticket_contract)

        # 3) create contract instance
        contract = polygon_web3.eth.contract(abi=abi, bytecode=bytecode)

        nftPrice = polygon_web3.toWei(0.01, 'ether')
        nftId = 123
        initialStock = 30
        royaltyReceiver = "0xF9D3E93c5C14Cbdbe8354C7F79C4316d51E4d6f4"
        royaltyPercentage = 500 # 5% represented in basis points, 100 basis points is 1%
        uri = "https://boomslag.com/api/courses/nft/"

        constructor_args = [
            nftId,
            nftPrice, 
            initialStock, 
            royaltyReceiver, 
            royaltyPercentage, 
            [owner_wallet, user_address], 
            [40, 60],
            uri
        ]
        # 4) Estimate deployment gas cost
        gas_estimate = contract.constructor(*constructor_args).estimateGas({
            'from': user_polygon_address
        })

        deployment_cost = polygon_web3.fromWei(gas_estimate * polygon_web3.eth.gasPrice, 'ether')
        print(f"Deployment cost: {deployment_cost} MATIC")
        return self.send_response(deployment_cost,status=status.HTTP_200_OK)


def check_verify_polygon_contract(result):
    
    url = 'https://api-testnet.polygonscan.com/api'
    # if DEBUG:
    #     url = f'https://api-testnet.polygonscan.com/api'
    # else:
    #     url = f'https://api.polygonscan.com/api'

    payload = {
        'apikey': POLYGONSCAN_API_KEY,
        'guid': result,
        'module': "contract",
        'action': "checkverifystatus",
    }

    response = requests.post(url, data=payload).json()
    status = response.get('status')
    if status == '1':
        return True
    return False

def verify_polygon_contract(api_keys, contract_address, source_code, contract_name, compiler_version, constructor_arguments):
    random.shuffle(api_keys)
    for api_key in api_keys:
        url = 'https://api-testnet.polygonscan.com/api'
        # if DEBUG:
        #     url = f'https://api-testnet.polygonscan.com/api'
        # else:
        #     url = f'https://api.polygonscan.com/api'

        payload = {
            'apikey': api_key,
            'module': 'contract',
            'action': 'verifysourcecode',
            'contractaddress': contract_address,
            'sourceCode': source_code,
            'contractname': contract_name,
            'compilerversion': compiler_version,
            'optimizationUsed': 0,
            'runs':200,
            'constructorArguements': constructor_arguments
        }

        response = requests.post(url, data=payload).json()
        status = response.get('status')
    
        if status == '1':
            result = response.get('result')

            
            if check_verify_polygon_contract(result, api_key):
                return True
    return False

contract_source_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/finance/PaymentSplitter.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/Strings.sol";


/// @custom:security-contact security@boomslag.com
contract Ticket is ERC1155, AccessControl, ERC1155Supply, PaymentSplitter,IERC2981 {
    // Define a constant role for the booth role
    bytes32 public constant BOOTH_ROLE = keccak256("BOOTH_ROLE");

    // Price of the NFT
    uint256 public price;
    // ID of the NFT
    uint256 public tokenId;
    // Stock limit for each token (0 means no limit)
    mapping(uint256 => uint256) public stock;
    // Add the unlimitedStock variable
    bool public unlimitedStock;
    // NFTs a user has minted for this ticket
    mapping(uint256 => mapping(address => uint256)) userNFTs;
    // Address to receive royalties
    address public royaltyReceiver;
    // Percentage of royalties to be paid (out of 10000)
    uint256 public royaltyPercentage;
    
    constructor(
        uint256 _tokenId, // ID of the NFT
        uint256 _price, // Price of the NFT
        uint256 _initialStock, // Initial stock of the NFT
        address _royaltyReceiver, // Address to receive royalties
        uint256 _royaltyPercentage, // Percentage of royalties to be paid (out of 10000)
        address[] memory _payees, // List of addresses to receive payments
        uint256[] memory _shares, // List of corresponding shares for each payee
        string memory _uri // Base URI for the NFT
    ) 
    ERC1155(_uri) 
    PaymentSplitter(_payees, _shares)
    {
        // set the tokenID, a random integer number
        tokenId = _tokenId;
        // Set the price for the token
        price = _price;
        // Set the unlimitedStock value based on the initial stock
        unlimitedStock = _initialStock == 0;
        if (!unlimitedStock) {
            stock[tokenId] = _initialStock;
        }
        royaltyReceiver = _royaltyReceiver;
        royaltyPercentage = _royaltyPercentage;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BOOTH_ROLE, msg.sender);
    }

    event Mint(uint256 indexed id, uint256 qty);
    event SetUri(string newuri);
    event Stop();
    event Start();

    // Function to retrieve royalty information for a given token and sale price
    function royaltyInfo(uint256 _tokenId, uint256 _salePrice) external view override returns (address receiver, uint256 royaltyAmount) {
        receiver = royaltyReceiver;
        royaltyAmount = (_salePrice * royaltyPercentage) / 10000;
    }
    // Function to set the stock limit for a given token
    function setStock(uint256 _tokenId, uint256 _stock) public onlyRole(DEFAULT_ADMIN_ROLE) {
        stock[_tokenId] = _stock;
    }
    // Function to set the NFT URI metadata
    function setURI(string memory newuri) public onlyRole(DEFAULT_ADMIN_ROLE) {
        // Sets the new URI for the token
        _setURI(newuri);
        // Emits an event with the new URI
        emit SetUri(newuri);
    }
    // Function to Update NFT price
    function updatePrice(uint256 newPrice) public onlyRole(DEFAULT_ADMIN_ROLE) {
        // Updates the price of the NFT ticket
        price = newPrice;
    }
    // Function to mint NFTs
    function mint(uint256 _tokenId, uint256 _nftId, uint256 _qty, address _guy) public payable {
        // If the caller is not the BOOTH_ROLE, apply the requirement
        if (!hasRole(BOOTH_ROLE, msg.sender)) {
            require(msg.value >= price * _qty, "Not Enough ETH to Buy NFT");
        }
        // Check if the NFT stock limit has been reached
        if (!unlimitedStock) {
            uint256 remainingStock = stock[_tokenId];
            require(remainingStock >= _qty, "NFT Out of Stock");
            // Update the stock mapping
            stock[_tokenId] = remainingStock - _qty;
        }
        // Mint new NFTs to the user and emit an event
        _mint(_guy, _nftId, _qty, "");
        emit Mint(_nftId, _qty);
        // Record the NFTs that the user has minted for this ticket
        userNFTs[_tokenId][_guy] = _nftId;
    }
    // Function to get the remaining stock of a token
    function getStock(uint256 _tokenId) public view returns (int256) {
        if (unlimitedStock) {
            return -1;
        } else {
            // Calculate the remaining stock by subtracting the total supply from the stock limit
            return int256(stock[_tokenId]) - int256(totalSupply(_tokenId));
        }
    }
    // Function to Verify User has access to NFT, see if it is in his balance
    function hasAccess(uint256 ticketId, address usr) public view returns (bool) {
        // Retrieves the NFT ID that the user has minted for the specified ticket
        uint256 nftId = userNFTs[ticketId][usr];
        // Checks if the user has an NFT for the specified ticket
        return balanceOf(usr, nftId) > 0;
    }
    // Function to Get NFT Metadata
    function uri(uint256 _id) public view virtual override returns (string memory) {
        // Checks if the specified token exists
        require(exists(_id),"URI: Token does not exist.");
        // Retrieves the URI for the token and appends the token ID to the end of the URI
        return string(abi.encodePacked(super.uri(_id),Strings.toString(_id), ".json" ));
    }
    // Function to Mint Multiple NFTs at Once
    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        // Mints a batch of NFTs to the specified address
        _mintBatch(to, ids, amounts, data);
    }

    function _beforeTokenTransfer(address operator, address from, address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)
        internal
        override(ERC1155, ERC1155Supply)
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
        // Assuming only one token is transferred at a time
    }
    // The following functions are overrides required by Solidity.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, AccessControl, IERC165)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
"""


class DeployNFTView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        payload = validate_token(request)

        data = request.data
        print(data)

        channel_layer = get_channel_layer()
        room_group_name = f"deploy_nft_{data['tokenId']}"
        async_to_sync(channel_layer.group_send)(
            room_group_name,
            {
                "type": "send_message",
                "message": {
                        "step1": True,
                        "step2": False,
                        "step3": False,
                    },
            },
        )
        
        price = float(data['price'])
                
        # Get User Private Key
        wallet_private_key = decrypt_polygon_private_key(data['userAddress'])

        ticketPrice = polygon_web3.toWei(price, 'ether')
        nftId = int(data['tokenId'])
        initialStock = int(data['stock'])
        sellerAddress = data['userPolygonAddress']
        royaltyAddress=sellerAddress
        royaltyPercentage=500# 5% represented in basis points, where 100 is 1%
        uri = f"https://boomslag.com/api/{data['uri']}/nft/"


        # Get Sellers
        platformFeeAddress = owner_wallet
        foundationFeeAddress = uridium_wallet
        team_members = data['teamMembers']
        platform_percentage = 35
        foundation_percentage = 5

        total_percentage = sum([member['percent'] for member in team_members])
        remaining_percentage = 100 - foundation_percentage - platform_percentage - total_percentage

        seller_addresses = [member['polygonAddress'] for member in team_members]
        seller_percentages = [member['percent'] + remaining_percentage * member['percent'] / total_percentage for member in team_members]
        seller_percentages = [round(percentage) for percentage in seller_percentages]

        # Combine platform and foundation fees with seller fees and addresses
        payees = [platformFeeAddress, foundationFeeAddress] + seller_addresses
        shares = [platform_percentage, foundation_percentage] + seller_percentages
        print(f"Ticket price: {ticketPrice}, NFT ID: {nftId}, Initial Stock: {initialStock}, Royalty address: {royaltyAddress}, Royalty percentage: {royaltyPercentage}, URI: {uri}, Payees: {payees}, Shares: {shares}")
        
        #  ======== DEPLOYMENT of NFT Contract ========
        # 1) Load the contract ABI
        ticket_location = os.path.join(settings.BASE_DIR, 'contracts', 'marketplace', 'ticket.sol')
        with open(os.path.join(ticket_location, 'Ticket.json'), "r") as f:
            contract_json = json.load(f)
        abi = contract_json['abi']
        bytecode = contract_json['bytecode']
        

        # # 2) create contract instance
        contract = polygon_web3.eth.contract(abi=abi, bytecode=bytecode)

        constructorArguments = [
            nftId,
            ticketPrice,
            initialStock,
            royaltyAddress,
            royaltyPercentage,
            payees,
            shares,
            uri
        ]

        transaction = contract.constructor(*constructorArguments).buildTransaction(
            {
                "gasPrice": polygon_web3.eth.gas_price,
                "from": sellerAddress,
                "nonce": polygon_web3.eth.getTransactionCount(data['userPolygonAddress']),
                # "gas": 600000,
            }
        )

        sign_tx = polygon_web3.eth.account.sign_transaction(transaction,wallet_private_key)
        txHash = polygon_web3.eth.send_raw_transaction(sign_tx.rawTransaction)
        txReceipt = polygon_web3.eth.wait_for_transaction_receipt(txHash)
        transaction_hash = txReceipt.get('transactionHash').hex()

        responseDictionary = {
            'contractAddress':txReceipt.get('contractAddress'),
            'gasUsed':txReceipt.get('gasUsed'),
            'transactionHash':transaction_hash
            # 'contractAddress':'0x123Qwer',
            # 'gasUsed':'0.0',
            # 'transactionHash':'0x123Qwer'
        }

        contract_address = txReceipt.get('contractAddress')

        sleep(30)

        channel_layer = get_channel_layer()
        room_group_name = f"deploy_nft_{data['tokenId']}"
        async_to_sync(channel_layer.group_send)(
            room_group_name,
            {
                "type": "send_message",
                "message": {
                        "step1": False,
                        "step2": True,
                        "step3": False,
                    },
            },
        )

        verify_polygon_contract(
            api_keys,
            contract_address,
            contract_source_code,
            'Ticket',
            'v0.8.9+commit.e5eed63a',
            constructorArguments
        )

        sleep(30)

        channel_layer = get_channel_layer()
        room_group_name = f"deploy_nft_{data['tokenId']}"
        async_to_sync(channel_layer.group_send)(
            room_group_name,
            {
                "type": "send_message",
                "message": {
                        "step1": False,
                        "step2": False,
                        "step3": True,
                    },
            },
        )

        # Register NFT in BOOTH Marketplace
        abi_booth = get_polygon_contract_abi(booth_contract)
        booth_contract_instance = polygon_web3.eth.contract(abi=abi_booth, address=booth_contract)

        transaction_params = {
            'from': owner_wallet,
            'nonce': polygon_web3.eth.get_transaction_count(owner_wallet),
            'gasPrice': polygon_web3.eth.gas_price,
        }

        register_object_function = booth_contract_instance.functions.registerObject(nftId, contract_address)
        gas_estimate = register_object_function.estimateGas(transaction_params)
        transaction_params['gas'] = gas_estimate

        tx_booth = register_object_function.buildTransaction(transaction_params)

        signed_tx_booth = polygon_web3.eth.account.sign_transaction(tx_booth, private_key=owner_wallet_key)
        tx_hash_booth = polygon_web3.eth.send_raw_transaction(signed_tx_booth.rawTransaction)
        txReceipt_booth = polygon_web3.eth.wait_for_transaction_receipt(tx_hash_booth)
        # Check if the transaction was successful
        if txReceipt_booth['status'] == 1:
            print("Successfully registered the NFT in the Booth contract.")
        else:
            print("Failed to register the NFT in the Booth contract.")
            return self.send_error('Failed to register the NFT in the Booth contract', status=status.HTTP_400_BAD_REQUEST)
        
        sleep(30)
        
        # Grant the booth role to the booth contract
        print("Granting the BOOTH Role to Booth contract.")
        ticket_instance = polygon_web3.eth.contract(abi=abi, address=contract_address)
        booth_role = ticket_instance.functions.BOOTH_ROLE().call()
        grant_role_txn = ticket_instance.functions.grantRole(booth_role, booth_contract).buildTransaction(
            {
                "from": sellerAddress,
                "gasPrice": polygon_web3.eth.gas_price,
                "nonce": polygon_web3.eth.getTransactionCount(data['userPolygonAddress']),
            }
        )
        sign_grant_role_txn = polygon_web3.eth.account.sign_transaction(grant_role_txn, wallet_private_key)
        grant_role_txHash = polygon_web3.eth.send_raw_transaction(sign_grant_role_txn.rawTransaction)
        grant_role_txReceipt = polygon_web3.eth.wait_for_transaction_receipt(grant_role_txHash)

        if grant_role_txReceipt['status'] == 1:
            print("Successfully Granted BOOTH Role to Booth contract.")
        else:
            print("Failed to grant booth role.")
            return self.send_error('Failed to register the NFT in the Booth contract', status=status.HTTP_400_BAD_REQUEST)

        return self.send_response(responseDictionary, status=status.HTTP_200_OK)


class BecomeAffiliateView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, format=None):
        validate_token(request)
        data= request.data
        polygon_address = data['polygonAddress']
        # Build Instance of Contract
        wallet_private_key = decrypt_polygon_private_key(data['address'])
        ticket_id = data['ticketId']
        # contract_address = data['address']
        # Register NFT in BOOTH Marketplace
        abi_booth = get_polygon_contract_abi(booth_contract)
        booth_contract_instance = polygon_web3.eth.contract(abi=abi_booth, address=booth_contract)
        isObjectRegistered = booth_contract_instance.functions.isObjectRegistered(int(ticket_id)).call()
        if not isObjectRegistered:
            return self.send_error('NFT not registered in booth')

        abi_affiliates = get_polygon_contract_abi(affiliates_contract)
        affiliate_contract_instance = polygon_web3.eth.contract(abi=abi_affiliates, address=affiliates_contract)
        # Get the AFFILIATE_ROLE from the contract
        affiliate_role = affiliate_contract_instance.functions.AFFILIATE_ROLE().call()
        # Check if the user has the BUYER_ROLE
        hasAffiliateRole = affiliate_contract_instance.functions.hasRole(affiliate_role, polygon_address).call()

        if not hasAffiliateRole:
            print(f"Granting affiliate role to {polygon_address}")
            grant_role_txn = affiliate_contract_instance.functions.grantRole(affiliate_role, polygon_address).buildTransaction(
                {
                    "from": owner_wallet,
                    "nonce": polygon_web3.eth.getTransactionCount(owner_wallet),
                    "gasPrice": polygon_web3.eth.gas_price,
                }
            )
            sign_grant_role_txn = polygon_web3.eth.account.sign_transaction(grant_role_txn, owner_wallet_key)
            grant_role_txHash = polygon_web3.eth.send_raw_transaction(sign_grant_role_txn.rawTransaction)
            grant_role_txReceipt = polygon_web3.eth.wait_for_transaction_receipt(grant_role_txHash)

            if grant_role_txReceipt['status'] == 1:
                print(f"Successfully Granted Affiliate Role to {polygon_address}.")
            else:
                print("Failed to grant affiliate role.")
                return self.send_error('Failed to register the NFT in the Booth contract', status=status.HTTP_400_BAD_REQUEST)


            become_affiliate_tx = booth_contract_instance.functions.joinAffiliateProgram(int(ticket_id), uridium_wallet).buildTransaction(
                {
                    "from": polygon_address,
                    "nonce": polygon_web3.eth.getTransactionCount(polygon_address),
                    "gasPrice": polygon_web3.eth.gas_price,
                    "gas": 600000,
                }
            )
            sign_become_affiliate_txn = polygon_web3.eth.account.sign_transaction(become_affiliate_tx, wallet_private_key)
            become_affiliate_txHash = polygon_web3.eth.send_raw_transaction(sign_become_affiliate_txn.rawTransaction)
            become_affiliate_txReceipt = polygon_web3.eth.wait_for_transaction_receipt(become_affiliate_txHash)
            print(become_affiliate_txReceipt)
            if become_affiliate_txReceipt['status'] == 1:
                print(f"User {polygon_address} Successfully became Affiliate for NFT: {ticket_id}")
                return self.send_response(True, status=status.HTTP_200_OK)
            else:
                print(f"User {polygon_address} FAILED to become Affiliate for NFT: {ticket_id}")
                return self.send_error('Failed to Become Affiliate', status=status.HTTP_400_BAD_REQUEST)
        else:
            print(f"User {polygon_address} already has affiliate Role")
            # return self.send_error(False)
            print(f"User {polygon_address} joining Affiliate Program for NFT: {ticket_id}")
            become_affiliate_tx = booth_contract_instance.functions.joinAffiliateProgram(int(ticket_id), uridium_wallet).buildTransaction(
                {
                    "from": polygon_address,
                    "nonce": polygon_web3.eth.getTransactionCount(polygon_address),
                    "gasPrice": polygon_web3.eth.gas_price,
                    "gas": 600000,
                }
            )
            sign_become_affiliate_txn = polygon_web3.eth.account.sign_transaction(become_affiliate_tx, wallet_private_key)
            become_affiliate_txHash = polygon_web3.eth.send_raw_transaction(sign_become_affiliate_txn.rawTransaction)
            become_affiliate_txReceipt = polygon_web3.eth.wait_for_transaction_receipt(become_affiliate_txHash)
            # print(become_affiliate_txReceipt)
            if become_affiliate_txReceipt['status'] == 1:
                print(f"User {polygon_address} Successfully became Affiliate for NFT: {ticket_id}")
                return self.send_response(True, status=status.HTTP_200_OK)
            else:
                print(f"User {polygon_address} FAILED to become Affiliate for NFT: {ticket_id}")
                return self.send_error('Failed to Become Affiliate', status=status.HTTP_400_BAD_REQUEST)


class VerifyAffiliateView(StandardAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, format=None):
        # payload = validate_token(request)
        data= request.data
        polygon_address = data['polygon_address']
        # Build Instance of Contract
        ticket_id = int(data['ticket_id'])
        # print(ticket_id)
        abi_booth = get_polygon_contract_abi(booth_contract)
        booth_contract_instance = polygon_web3.eth.contract(abi=abi_booth, address=booth_contract)
        # balance = contract.functions.get_balance(payload['polygon_address'])
        result = booth_contract_instance.functions.verifyAffiliate(ticket_id,polygon_address).call()
        return self.send_response(result, status=status.HTTP_200_OK)
