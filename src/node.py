import os
import json
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey
from nacl.hash import sha256

def create_dummy_transaction():
    sk = SigningKey.generate()
    vk = sk.verify_key
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


def verify_transaction(verify_key_hex, signed_hex):
    # Create a VerifyKey object from a hex serialized public key
    verify_key = VerifyKey(verify_key_hex, encoder=HexEncoder)

    # Check the validity of a message's signature
    # return signed_hex.message if pass else raise error
    verify_key.verify(signed_hex, encoder=HexEncoder)