import os
from asyncio import run
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import dataclass
from ipv8.types import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
import time

signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

@dataclass(msg_id=99)
class Transaction:
    nonce: str
    signature: str
    public_key: str

class MyCommunity(Community):
    community_id = b'harbourspaceuniverse'

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Register the message handler for messages (with the identifier "99").
        self.add_message_handler(Transaction, self.on_transaction)
        self.msg = ''

    def started(self) -> None:
        async def start_communication() -> None:
            if not self.msg:
                # Generate and send a transaction to known peers
                transaction = self.create_dummy_transaction()
                for p in self.get_peers():
                    self.ez_send(p, transaction)
            else:
                self.cancel_pending_task("start_communication")

        self.register_task("start_communication", start_communication, interval=5.0, delay=0)

    def create_dummy_transaction(self):
        nonce = os.urandom(16).hex()
        message = nonce.encode()
        signature = signing_key.sign(message, encoder=HexEncoder).signature.decode()
        public_key = verify_key.encode(encoder=HexEncoder).decode()
        transaction = Transaction(nonce, signature, public_key)
        return transaction

    @lazy_wrapper(Transaction)
    def on_transaction(self, peer: Peer, payload: Transaction) -> None:
        print(f"Received transaction from {peer}:")
        print(f"Nonce: {payload.nonce}")
        print(f"Signature: {payload.signature}")
        print(f"Public Key: {payload.public_key}")
        transaction = self.create_dummy_transaction()
        self.ez_send(peer, transaction)
        self.crypto


def verify_transaction(verify_key_hex, signed_hex):
    # Create a VerifyKey object from a hex serialized public key
    verify_key = VerifyKey(verify_key_hex, encoder=HexEncoder)

    # Check the validity of a message's signature
    # return signed_hex.message if pass else raise error
    verify_key.verify(signed_hex, encoder=HexEncoder)





async def start_communities() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "medium", f"ec{os.getenv('PID', 0)}.pem")

    builder.add_overlay("MyCommunity", "my peer",
                        [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                        default_bootstrap_defs, {}, [('started',)])
    await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity}).start()
    await run_forever()

run(start_communities())