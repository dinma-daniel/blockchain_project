import random
import hashlib
from merkle import MerkleTree
from collections import defaultdict

from ipv8.community import CommunitySettings
from ipv8.messaging.payload_dataclass import overwrite_dataclass
from dataclasses import dataclass, field
from typing import List, Dict, Any, Union
from ipv8.types import Peer

from da_types import Blockchain, message_wrapper
import time

# We are using a custom dataclass implementation.
dataclass = overwrite_dataclass(dataclass)


@dataclass(msg_id=11)
class TransactionPayload:
    sender: int
    receiver: int
    amount: int
    nonce: int
    
@dataclass(msg_id=12)
class NFTTransactionPayload:
    sender: int
    receiver: int
    token_id: int
    timestamp: int

@dataclass(msg_id=13)
class RewardTransactionPayload:
    receiver: int
    amount: int


@dataclass(msg_id=1)
class Transaction:
    payload: TransactionPayload
    pk: bytes
    sign: bytes
        
@dataclass(msg_id=2)
class NFTTransaction:
    payload: NFTTransactionPayload
    pk: bytes
    sign: bytes
    image_path: str

    def to_dict(self):
        return {
            "sender": self.payload.sender,
            "receiver": self.payload.receiver,
            "token_id": self.payload.token_id,
            "timestamp": self.payload.timestamp,
            "sign": self.sign.hex(),
            "image_path": self.image_path
        }

@dataclass(msg_id=3)
class RewardTransaction:
    payload: RewardTransactionPayload
    pk: bytes
    sign: bytes
    

@dataclass(msg_id=90)
class Block:
    previous_hash: str
    merkle_root: str
    nonce: int
    transactions: List[Transaction]
    timestamp: int
    creator: int

    def calculate_hash(self):
        block_string = f"{self.previous_hash}{self.merkle_root}{self.nonce}{self.timestamp}{self.creator}"
        return hashlib.sha256(block_string.encode()).hexdigest()

@dataclass(
    msg_id=99
)
class BlockMessage:
    block: Block

@dataclass(msg_id=100)
class NFTTransactionMessage:
    nft: NFTTransaction

class BlockchainNode(Blockchain):
    community_id = b'harbourspaceuniverse'
    reward_amount = 50
    difficulty = 4

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.block_creation_in_progress = False
        self.counter = 1
        self.block_size = 3
        self.executed_checks = 0

        self.pending_txs = []
        self.nfts = []
        self.balances = defaultdict(lambda: 1000)
        
        self.blockchain = []

        self.add_message_handler(Transaction, self.on_transaction)
        # self.add_message_handler(NFTTransactionMessage, self.on_nft)
        self.add_message_handler(BlockMessage, self.on_block_message)

    def create_genesis_block(self):
        transactions = []  # Genesis block has no transactions
        merkle_tree = MerkleTree(transactions)
        merkle_root = merkle_tree.getRootHash()

        previous_hash = "0" * 64
        genesis_timestamp = int(time.time())
        nonce, block_hash = self.solve_puzzle(previous_hash, merkle_root, genesis_timestamp, self.node_id)

        genesis_block = Block(
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            nonce=nonce,
            transactions=transactions,
            timestamp=genesis_timestamp,
            creator=self.node_id 
        )

        self.blockchain.append(block_hash)
        self.broadcast_block(genesis_block)
        print("Genesis block created", block_hash)

    def on_start(self):
        print(f'[Node {self.node_id}] Community started with ID: {self.community_id}')
        if self.node_id == 0: # should be fine for demo =3
            self.create_genesis_block()

        self.start_validator()

    def create_transaction(self, sender, receiver, amount):
        txp = TransactionPayload(sender, receiver, amount, self.counter)
        
        blob = self.serializer.pack_serializable(txp)
        sign = self.crypto.create_signature(self.my_peer.key, blob)
        pk = self.my_peer.key.pub().key_to_bin()
        tx = Transaction(txp, pk, sign)
    
        self.counter += 1
        self.pending_txs.append(tx)
        
        print(f'[Node {self.node_id}] Created transaction from {sender} to {receiver} for {amount} amount')
        self.broadcast_tx(tx)
        return self.counter

    def create_reward_transaction(self):
        txp = RewardTransactionPayload(self.node_id, self.reward_amount)
        
        blob = self.serializer.pack_serializable(txp)
        sign = self.crypto.create_signature(self.my_peer.key, blob)
        pk = self.my_peer.key.pub().key_to_bin()
        tx = RewardTransaction(txp, pk, sign)
    
        self.counter += 1
        print(f'[Node {self.node_id}] Created reward transaction for node {self.node_id} with amount {self.reward_amount}')
        return tx

    def create_nft(self, sender, receiver, token_id, image_path):
        timestamp = int(time.time())
        nft_payload = NFTTransactionPayload(sender, receiver, token_id, timestamp)
        
        blob = self.serializer.pack_serializable(nft_payload)
        sign = self.crypto.create_signature(self.my_peer.key, blob)
        pk = self.my_peer.key.pub().key_to_bin()
        nft = NFTTransaction(nft_payload, pk, sign, image_path)
    
        self.counter += 1
        # self.pending_txs.append(nft)
        self.nfts.append(nft)
        self.broadcast_nft(nft)
        print(f'[Node {self.node_id}] Created NFT transaction from {sender} to {receiver} for image {image_path}')
        return nft

    def create_block(self):
        if len(self.pending_txs) < self.block_size:
            return # not enough txs to create a block

        self.block_creation_in_progress = True
        reward_tx = self.create_reward_transaction()
        transactions = self.pending_txs[:self.block_size] # + [reward_tx]

        transaction_ids = [self.generate_transaction_id(tx) for tx in transactions]
        merkle_tree = MerkleTree(transaction_ids)

        merkle_root = merkle_tree.getRootHash()
        previous_hash = self.get_previous_block_hash()
        block_timestamp = int(time.time())
        nonce, block_hash = self.solve_puzzle(previous_hash, merkle_root, block_timestamp, self.node_id)

        block = Block(previous_hash, merkle_root, nonce, transactions, block_timestamp, self.node_id)

        if self.block_creation_in_progress:
            self.broadcast_block(block)

            self.blockchain.append(block_hash)
            self.apply_block_transactions(block)
            self.pending_txs = self.pending_txs[self.block_size:]
            self.block_creation_in_progress = False
            print(f"[Node {self.node_id}] Created block with nonce {nonce} and hash {block_hash}")

    def generate_transaction_id(self, tx):
        if isinstance(tx.payload, TransactionPayload):
            return f"{tx.payload.sender}-{tx.payload.receiver}-{tx.payload.amount}-{tx.payload.nonce}"
        elif isinstance(tx.payload, RewardTransactionPayload):
            return f"reward-{tx.payload.receiver}-{tx.payload.amount}"
        elif isinstance(tx.payload, NFTTransactionPayload):
            return f"nft-{tx.payload.sender}-{tx.payload.receiver}-{tx.payload.token_id}-{tx.payload.timestamp}"
        
    def get_previous_block_hash(self):
        if not self.blockchain:
            return "0" * 64
        return self.blockchain[-1]

    def solve_puzzle(self, previous_hash, merkle_root, timestamp, creator):
        target = '0' * self.difficulty
        nonce = 0
        while True:
            block_string = f"{previous_hash}{merkle_root}{nonce}{timestamp}{creator}"
            block_hash = hashlib.sha256(block_string.encode()).hexdigest()
            if block_hash.startswith(target):
                return nonce, block_hash
            nonce += 1

    def broadcast_tx(self, tx: Transaction):
        for peer in self.get_peers():
            self.ez_send(peer, tx)

    def broadcast_block(self, block: Block):
        block_message = BlockMessage(block)
        for peer in self.get_peers():
            self.ez_send(peer, block_message)

    def broadcast_nft(self, nft: NFTTransaction):
        nft_message = NFTTransactionMessage(nft)
        for peer in self.get_peers():
            self.ez_send(peer, nft_message)

    def start_validator(self):
        self.register_task("show_balance", self.show_balance, delay=1, interval=10)
        self.register_task("create_block", self.create_block, delay=2, interval=5)
        
    def verify_sign_of_tx(self, transaction) -> bool:
        pk = self.crypto.key_from_public_bin(transaction.pk)
        blob = self.serializer.pack_serializable(transaction.payload)
        return self.crypto.is_valid_signature(pk, blob, transaction.sign)

    def show_balance(self):
        print(f'[Node {self.node_id}] balance: {self.balances}')
        print(f'[Node {self.node_id}] chain: {self.blockchain}')    

    def verify_tx(self, tx) -> bool:
        if isinstance(tx.payload, TransactionPayload):
            if self.balances[tx.payload.sender] - tx.payload.amount < 0:
                return False
        return self.verify_sign_of_tx(tx)

    def verify_block(self, block: Block) -> bool:
        if block.previous_hash != self.get_previous_block_hash():
            print(f"[Node {self.node_id}] Block rejected: mismatched previous hash.")
            return False
        
        transaction_ids = [self.generate_transaction_id(tx) for tx in block.transactions]

        merkle_tree = MerkleTree(transaction_ids)
        if block.merkle_root != merkle_tree.getRootHash():
            print(f"[Node {self.node_id}] Block rejected: invalid Merkle root.")
            return False

        for tx in block.transactions:
            if not self.verify_tx(tx):
                print(f"[Node {self.node_id}] Block rejected: invalid transaction: {tx}")
                return False

        if not block.calculate_hash().startswith('0' * self.difficulty):
            print(f"[Node {self.node_id}] Block rejected: insufficient proof of work.")
            return False

        return True
    
    def apply_block_transactions(self, block: Block):
        for tx in block.transactions:
            if isinstance(tx.payload, TransactionPayload):
                self.balances[tx.payload.sender] -= tx.payload.amount
                self.balances[tx.payload.receiver] += tx.payload.amount
            elif isinstance(tx.payload, RewardTransactionPayload):
                self.balances[tx.payload.receiver] += tx.payload.amount
            elif isinstance(tx.payload, NFTTransactionPayload):
                self.transfer_nft(tx.payload.token_id, tx.payload.sender, tx.payload.receiver)

    def transfer_nft(self, token_id, sender, receiver):
        for nft in self.nfts:
            if nft.payload.token_id == token_id and nft.payload.sender == sender:
                nft.payload.sender = receiver
                return
        print(f'Error: NFT with token ID {token_id} not found or invalid sender.')

    @message_wrapper(Transaction)
    async def on_transaction(self, peer: Peer, payload: Transaction) -> None:
        if self.verify_tx(payload):
            if (payload.payload.sender, payload.payload.nonce) not in [(tx.payload.sender, tx.payload.nonce) for tx in self.pending_txs]:
                self.pending_txs.append(payload)

    @message_wrapper(NFTTransactionMessage)
    async def on_nft(self, peer: Peer, payload: NFTTransactionMessage) -> None:
        nft = payload.nft
        if self.verify_nft(nft):
            if (nft.payload.sender, nft.payload.timestamp) not in [(n.payload.sender, n.payload.timestamp) for n in self.nfts]:
                self.apply_nft(nft)

    @message_wrapper(BlockMessage)
    async def on_block_message(self, peer: Peer, payload: BlockMessage) -> None:
        block = payload.block
        block_hash = block.calculate_hash()
        print('received', block_hash)

        if self.verify_block(block):
            self.block_creation_in_progress = False
            self.blockchain.append(block_hash)
            self.apply_block_transactions(block)
            print(f"[Node {self.node_id}] Block {block_hash} added to the chain.")
