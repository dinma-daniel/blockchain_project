from flask import Flask, request, redirect, url_for, render_template, jsonify
from blockchain import BlockchainNode, CommunitySettings
import os

APP_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(APP_PATH, 'templates/')

app = Flask(__name__)
settings = CommunitySettings()
blockchain_node = BlockchainNode(settings)

UPLOAD_FOLDER = 'NFT_storage'
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
        filepath = os.path.join('uploads', file.filename)
        file.save(filepath)
        nft = blockchain_node.create_nft(filepath, 'owner_public_key')
        return jsonify({'message': 'NFT created successfully', 'nft': nft})

@app.route('/transfer', methods=['POST'])
def transfer_nft():
    data = request.get_json()
    nft_hash = data['nft_hash']
    new_owner = data['new_owner']
    nft = blockchain_node.transfer_nft(nft_hash, new_owner)
    if nft:
        return jsonify({'message': 'NFT transferred successfully', 'nft': nft})
    return jsonify({'error': 'NFT not found'})

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': [block.__dict__ for block in blockchain_node.blockchain],
        'length': len(blockchain_node.blockchain),
    }
    return jsonify(response), 200

@app.route('/stats', methods=['GET'])
def get_stats():
    num_transactions = [len(block.transactions) for block in blockchain_node.blockchain]
    return jsonify({'transactions_over_time': num_transactions})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
