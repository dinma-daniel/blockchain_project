import os
import json
import ecdsa
from hashlib import sha256

def generate_key_pair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk

def create_dummy_transaction(sk):
    nonce = os.urandom(16).hex()
    message = nonce.encode()
    signature = sk.sign(message)
    vk = sk.get_verifying_key()
    transaction = {
        'nonce': nonce,
        'signature': signature.hex(),
        'public_key': vk.to_string().hex()
    }
    return json.dumps(transaction)

sk, vk = generate_key_pair()
transaction = create_dummy_transaction(sk)
print("Created transaction:", transaction)