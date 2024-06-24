import os
import json
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from nacl.hash import sha256

# using libsodium for key generation
def generate_key_pair():
    sk = SigningKey.generate()
    vk = sk.verify_key
    return sk, vk

def create_dummy_transaction(sk):
    nonce = os.urandom(16).hex()
    message = nonce.encode()
    signature = sk.sign(message, encoder=HexEncoder).signature.decode()
    vk = sk.verify_key.encode(encoder=HexEncoder).decode()
    transaction = {
        'nonce': nonce,
        'signature': signature,
        'public_key': vk
    }
    return json.dumps(transaction)

sk, vk = generate_key_pair()
transaction = create_dummy_transaction(sk)
print("Created transaction:", transaction)
