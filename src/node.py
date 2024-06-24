import os
import json
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from nacl.hash import sha256

# using libsodium for key generation
sk = SigningKey.generate()
vk = sk.verify_key

def create_dummy_transaction():
    nonce = os.urandom(16).hex()
    message = nonce.encode()
    signature = sk.sign(message, encoder=HexEncoder).signature.decode()
    vk_hex = vk.encode(encoder=HexEncoder).decode()
    transaction = {
        'nonce': nonce,
        'signature': signature,
        'public_key': vk_hex
    }
    return transaction
