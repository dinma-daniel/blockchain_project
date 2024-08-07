import random
import hashlib
from merkle import MerkleTree
from collections import defaultdict

from ipv8.community import CommunitySettings
from ipv8.messaging.payload_dataclass import overwrite_dataclass
from dataclasses import dataclass

from ipv8.types import Peer

from da_types import Blockchain, message_wrapper
from typing import List
import time

# We are using a custom dataclass implementation.
dataclass = overwrite_dataclass(dataclass)


@dataclass()
class TransactionPayload:
    sender: int
    receiver: int
    nft: int
    nonce: int = 1


@dataclass(msg_id=1)
class Transaction:
    payload: TransactionPayload
    pk: bytes
    sign: bytes


@dataclass(msg_id=90)
class Block:
    previous_hash: str
    merkle_root: str
    nonce: int
    transactions: List[Transaction]
    timestamp: int

    def compute_hash(self):
        block_string = f"{self.previous_hash}{self.merkle_root}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

@dataclass(
    msg_id=99
)
class BlockMessage:
    block: Block

class BlockchainNode(Blockchain):
    community_id = b'harbourspaceuniverse'

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.counter = 1
        self.block_size = 3
        self.executed_checks = 0

        self.pending_txs = []
        self.finalized_txs = []
        self.balances = defaultdict(lambda: 1000)
        self.blockchain = []

        self.add_message_handler(Transaction, self.on_transaction)
        self.add_message_handler(BlockMessage, self.on_block_message)

    def on_start(self):
        print(f'[Node {self.node_id}] Community started with ID: {self.community_id}')
        if self.node_id % 2 == 0:
            self.start_client()
        else:
            self.start_validator()

    def on_upload(self, img_code):
        print(f'[Node {self.node_id}] Uploaded an image: {img_code}')
        tx = self.sign_transaction(self.node_id, self.node_id, img_code, 0)

        self.counter += 1
        for peer in self.get_peers():
            print(f'[Node {self.node_id}] Sending transaction {tx.payload.nonce} to {self.node_id_from_peer(peer)}')
            self.ez_send(peer, tx)

    def on_transaction(self, sender, receiver, img_code):
        print(f'[Node {self.node_id}] Receiver {receiver} buy {img_code} from sender {sender}')
        tx = self.sign_transaction(sender, receiver, img_code, self.counter)

        self.counter += 1
        for peer in self.get_peers():
            print(f'[Node {self.node_id}] Sending transaction {tx.payload.nonce} to {self.node_id_from_peer(peer)}')
            self.ez_send(peer, tx)


    def sign_transaction(self, sender, receiver, img_code, nonce):
        txp = TransactionPayload(sender,
                    receiver,
                    img_code,
                    nonce,
                    )
        
        blob = self.serializer.pack_serializable(txp)
        sign = self.crypto.create_signature(self.my_peer.key, blob)
        pk = self.my_peer.key.pub().key_to_bin()
        tx = Transaction(txp, pk, sign)
        return tx, pk, sign

        

    def create_transaction(self):
        peers = [i for i in self.get_peers() if self.node_id_from_peer(i) is not None and self.node_id_from_peer(i) % 2 == 1]
        if not peers:
            print(f'[Node {self.node_id}] No valid peers found for creating transaction.')
            return

        peer = random.choice(peers)
        peer_id = self.node_id_from_peer(peer)

        txp = TransactionPayload(self.node_id,
                         peer_id,
                         10,
                         self.counter,
                         )
        
        blob = self.serializer.pack_serializable(txp)
        sign = self.crypto.create_signature(self.my_peer.key, blob)
        pk = self.my_peer.key.pub().key_to_bin()
        tx = Transaction(txp, pk, sign)
    
        self.counter += 1
        print(f'[Node {self.node_id}] Sending transaction {txp.nonce} to {self.node_id_from_peer(peer)}')
        self.ez_send(peer, tx)

    def create_block(self):
        if len(self.pending_txs) < self.block_size:
            return # not enough txs to create a block

        transactions = self.pending_txs[:self.block_size]
        
        # ugly reward
        # transactions += Transaction()

        self.pending_txs = self.pending_txs[self.block_size:]

        transaction_ids = [f"{tx.payload.sender}-{tx.payload.receiver}-{tx.payload.nft}-{tx.payload.nonce}" for tx in transactions]


        merkle_tree = MerkleTree(transaction_ids)
        merkle_root = merkle_tree.getRootHash()

        previous_hash = self.get_previous_block_hash()
        difficulty = 4
        nonce, block_hash = self.solve_puzzle(previous_hash, merkle_root, difficulty)

        block = Block(previous_hash, merkle_root, nonce, transactions, time.monotonic_ns() // 1_000)
        self.finalized_txs.extend(transactions)
        self.blockchain.append(block)
        self.broadcast_block(block)
        print(f"[Node {self.node_id}] Created block with nonce {nonce} and hash {block_hash}")

    def get_previous_block_hash(self):
        if not self.blockchain:
            return "0" * 64
        return self.blockchain[-1].compute_hash()

    def solve_puzzle(self, previous_hash, merkle_root, difficulty):
        target = '0' * difficulty
        nonce = 0
        while True:
            block = Block(previous_hash, merkle_root, nonce, [], time.monotonic_ns() // 1_000)
            block_hash = block.compute_hash()
            if block_hash.startswith(target):
                return nonce, block_hash
            nonce += 1

    def broadcast_block(self, block: Block):
        block_message = BlockMessage(block)
        for peer in self.get_peers():
            self.ez_send(peer, block_message)

    def start_client(self):
        self.register_task("tx_create",
                           self.create_transaction, delay=1,
                           interval=1)

    def start_validator(self):
        self.register_task("check_txs", self.check_transactions, delay=2, interval=1)
        self.register_task("create_block", self.create_block, delay=5, interval=5)
        
    def verify_sign_transaction(self, transaction: Transaction) -> bool:
        pk = self.crypto.key_from_public_bin(transaction.pk)
        blob = self.serializer.pack_serializable(transaction.payload)
        if not self.crypto.is_valid_signature(pk, blob, transaction.sign):
            return False
        return True

    def check_transactions(self):
        for tx in self.pending_txs:
            if (self.balances[tx.payload.sender] - tx.payload.amount >= 0 and
                self.verify_sign_transaction(tx)):
                self.balances[tx.payload.sender] -= tx.payload.amount
                self.balances[tx.payload.receiver] += tx.payload.amount
                self.pending_txs.remove(tx)
                self.finalized_txs.append(tx)

        self.executed_checks += 1

        if self.executed_checks % 10 == 0:
            print(f'balance: {self.balances}')

    # redundant?
    def verify_transaction(self, tx: Transaction) -> bool:
        if (
            self.balances[tx.payload.sender] - tx.payload.amount >= 0 and
            self.verify_sign_transaction(tx)):
            return True
        return False

    def verify_block(self, block: Block) -> bool:
        print(f"[Node {self.node_id}] Verifying block with nonce {block.nonce} and hash {block.compute_hash()}")

        if block.previous_hash != self.get_previous_block_hash():
            print(f"[Node {self.node_id}] Block rejected due to mismatched previous hash.")
            return False
        
        transaction_ids = [f"{tx.payload.sender}-{tx.payload.receiver}-{tx.payload.amount}-{tx.payload.nonce}" for tx in block.transactions]
        merkle_tree = MerkleTree(transaction_ids)
        if block.merkle_root != merkle_tree.getRootHash():
            print(f"[Node {self.node_id}] Block rejected due to invalid Merkle root.")
            return False

        for tx in block.transactions:
            if not self.verify_transaction(tx):
                print(f"[Node {self.node_id}] Block rejected due to invalid transaction: {tx}")
                return False

        difficulty = 4
        if not block.compute_hash().startswith('0' * difficulty):
            print(f"[Node {self.node_id}] Block rejected due to insufficient proof of work.")
            return False

        print(f"[Node {self.node_id}] Block validated successfully.")
        return True
    
    def apply_block_transactions(self, block: Block):
        for tx in block.transactions:
            self.balances[tx.payload.sender] -= tx.payload.amount
            self.balances[tx.payload.receiver] += tx.payload.amount
        self.finalized_txs.extend(block.transactions)

    @message_wrapper(Transaction)
    async def on_transaction(self, peer: Peer, payload: Transaction) -> None:
        if self.verify_transaction(payload):
            if (payload.payload.sender, payload.payload.nonce) not in [(tx.payload.sender, tx.payload.nonce) for tx in self.finalized_txs] and (
            payload.payload.sender, payload.payload.nonce) not in [(tx.payload.sender, tx.payload.nonce) for tx in self.pending_txs]:
                self.pending_txs.append(payload)

            # Gossip to other nodes
            for peer in [i for i in self.get_peers() if self.node_id_from_peer(i) % 2 == 1]:
                self.ez_send(peer, payload)

    @message_wrapper(BlockMessage)
    async def on_block_message(self, peer: Peer, payload: BlockMessage) -> None:
        block = payload.block
        block_hash = block.compute_hash()
        print(f"[Node {self.node_id}] Received block with nonce {block.nonce} and hash {block_hash}")

        if self.verify_block(block):
            self.blockchain.append(block)
            self.apply_block_transactions(block)
            print(f"[Node {self.node_id}] Block added to the chain.")
