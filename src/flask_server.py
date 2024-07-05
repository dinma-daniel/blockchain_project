import os
import sys
import time
from flask import Flask, request, jsonify, render_template

def start_flask_app(blockchain_nodes, debug=False):
    APP_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    TEMPLATE_PATH = os.path.join(APP_PATH, 'src', 'web', 'templates')
    STATIC_PATH = os.path.join(APP_PATH, 'src', 'web', 'static')

    app = Flask(__name__, template_folder=TEMPLATE_PATH, static_folder=STATIC_PATH)

    UPLOAD_FOLDER = os.path.join(STATIC_PATH, 'NFT_storage')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'})
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'})
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            if get_blockchain_node(blockchain_nodes):
                token_id = int(time.time()) + 34543
                nft = blockchain_nodes[0].create_nft(0, 1, token_id, file.filename)
                return render_template('nft_index.html', nft_info=nft.to_dict())
            else:
                return render_template({'message': 'debug: NFT created successfully'})

    @app.route('/transfer', methods=['POST'])
    def transfer_nft():
        data = request.get_json()
        nft_hash = data['nft_hash']
        new_owner = data['new_owner']
        if get_blockchain_node(blockchain_nodes):
            nft = blockchain_nodes[0].transfer_nft(nft_hash, new_owner)
            if nft:
                return jsonify({'message': 'NFT transferred successfully', 'nft': nft})
            return jsonify({'error': 'NFT not found'})
        else:
            return jsonify({'error': 'debug: NFT not found'})

    @app.route('/stats', methods=['GET'])
    def full_chain():
        response = {}
        if get_blockchain_node(blockchain_nodes):
            response = {
                'chain': [block.__dict__ for block in blockchain_nodes[0].blockchain],
                'length': len(blockchain_nodes[0].blockchain),
                'num_transactions': [len(block.transactions) for block in blockchain_nodes[0].blockchain],
            }
        else:
            response = {'data': 'debug: no data'}
        return jsonify(response), 200

    @app.route('/transactions', methods=['GET'])
    def create_transaction():
        return render_template('transactions.html')

    @app.route('/transactions/new', methods=['POST'])
    def new_transaction():
        data = request.get_json()
        required = ['sender', 'receiver', 'amount']
        if not all(k in data for k in required):
            return 'Missing values', 400
        index = ''
        if get_blockchain_node(blockchain_nodes):
            index = blockchain_nodes[0].create_transaction(int(data['sender']), int(data['receiver']), int(data['amount']))
        else:
            index = 'debug: no data'
        return jsonify({'message': f'Transaction №{index} will be added to Block ???'})

    @app.route('/transactions/all', methods=['GET'])
    def get_transactions():
        tx_list = [
            {
                'payload': {
                    'sender': tx.payload.sender,
                    'receiver': tx.payload.receiver,
                    'amount': tx.payload.amount,
                    'nonce': tx.payload.nonce,
                },
                'pk': tx.pk.hex(),
                'sign': tx.sign.hex()
            } for tx in blockchain_nodes[0].pending_txs
        ]
        return jsonify({'transactions': tx_list})
    app.run(debug=debug, port=5001)

def get_blockchain_node(blockchain_nodes):
    if len(blockchain_nodes) > 0:
        return blockchain_nodes[0] 

if __name__ == "__main__":
    start_flask_app(None, True)
