from flask import Flask, request, jsonify, render_template
import os
import sys

def start_flask_app(blockchain_node, debug=True):
    APP_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    TEMPLATE_PATH = os.path.join(APP_PATH, 'src', 'web', 'templates')
    STATIC_PATH = os.path.join(APP_PATH, 'src', 'web', 'static')

    app = Flask(__name__, template_folder=TEMPLATE_PATH, static_folder=STATIC_PATH)

    UPLOAD_FOLDER = os.path.join(APP_PATH, 'NFT_storage')
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
            if blockchain_node:
                nft = blockchain_node.create_nft(filepath, 'owner_public_key')
                return jsonify({'message': 'NFT created successfully', 'nft': nft})
            else:
                return jsonify({'message': 'debug: NFT created successfully'})

    @app.route('/transfer', methods=['POST'])
    def transfer_nft():
        data = request.get_json()
        nft_hash = data['nft_hash']
        new_owner = data['new_owner']
        if blockchain_node:
            nft = blockchain_node.transfer_nft(nft_hash, new_owner)
            if nft:
                return jsonify({'message': 'NFT transferred successfully', 'nft': nft})
            return jsonify({'error': 'NFT not found'})
        else:
            return jsonify({'error': 'debug: NFT not found'})

    @app.route('/stats', methods=['GET'])
    def full_chain():
        response = {}
        if blockchain_node:
            response = {
                'chain': [block.__dict__ for block in blockchain_node.blockchain],
                'length': len(blockchain_node.blockchain),
                'num_transactions': [len(block.transactions) for block in blockchain_node.blockchain],
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
        if blockchain_node:
            index = blockchain_node.create_transaction(data['sender'], data['receiver'], data['amount'])
        else:
            index = 'debug: no data'
        return jsonify({'message': f'Transaction will be added to Block {index}'})

    app.run(debug=debug, port=5001)

if __name__ == "__main__":
    start_flask_app(None)