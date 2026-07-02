"""
PyChain REST API
────────────────
Run:  pip install flask flask-cors cryptography gunicorn
      python app.py

Endpoints:
  POST /wallet/new             → create wallet
  GET  /wallet/<address>       → get wallet info + balance
  GET  /wallets                → list all wallets + balances
  POST /transaction/new        → broadcast a signed transaction
  POST /mine                   → mine pending transactions
  GET  /chain                  → full blockchain
  GET  /chain/validate         → validate chain integrity
  GET  /block/<index>          → single block
  GET  /pending                → pending transactions
  GET  /balance/<address>      → address balance
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from blockchain import Blockchain, Wallet, Transaction
import time
import os

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

# Single shared blockchain instance
bc = Blockchain()


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ─────────────────────────────────────────────
#  WALLET ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/wallet/new", methods=["POST"])
def new_wallet():
    wallet = Wallet()
    wallet_dict = wallet.to_dict()
    bc.register_wallet(wallet_dict)
    return jsonify({
        "message": "Wallet created",
        "wallet": wallet_dict
    }), 201


@app.route("/wallet/<address>", methods=["GET"])
def get_wallet(address):
    wallet = bc.get_wallet(address)
    if not wallet:
        return jsonify({"error": "Wallet not found"}), 404
    return jsonify({
        "address": wallet["address"],
        "public_key": wallet["public_key"],
        "balance": bc.get_balance(address),
    })


@app.route("/wallets", methods=["GET"])
def list_wallets():
    balances = bc.get_all_balances()
    wallets = []
    for address, w in bc.wallets.items():
        wallets.append({
            "address": address,
            "balance": balances.get(address, 0.0),
        })
    return jsonify({"wallets": wallets, "count": len(wallets)})


# ─────────────────────────────────────────────
#  TRANSACTION ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/transaction/new", methods=["POST"])
def new_transaction():
    data = request.get_json()
    required = ["sender", "recipient", "amount"]
    if not all(f in data for f in required):
        return jsonify({"error": f"Missing fields: {required}"}), 400

    sender = data["sender"]
    recipient = data["recipient"]
    amount = float(data["amount"])

    if "private_key" in data and data["private_key"]:
        wallet = bc.get_wallet(sender)
        if not wallet:
            return jsonify({"error": "Sender wallet not found on this node"}), 404
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        import base64

        tx = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            public_key=wallet["public_key"],
        )
        try:
            priv = load_pem_private_key(
                data["private_key"].encode(), password=None, backend=default_backend()
            )
            sig = priv.sign(
                tx.to_signable_string().encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            tx.signature = base64.b64encode(sig).decode()
        except Exception as e:
            return jsonify({"error": f"Signing failed: {str(e)}"}), 400

    elif "public_key" in data and "signature" in data:
        tx = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            public_key=data["public_key"],
            signature=data["signature"],
        )
    else:
        return jsonify({"error": "Provide either private_key OR (public_key + signature)"}), 400

    success = bc.add_transaction(tx)
    if not success:
        balance = bc.get_balance(sender)
        return jsonify({
            "error": "Transaction rejected",
            "reason": f"Invalid signature or insufficient funds (balance: {balance})"
        }), 400

    return jsonify({
        "message": "Transaction added to pool",
        "transaction": tx.to_dict(),
        "pool_size": len(bc.pending_transactions),
    }), 201


@app.route("/pending", methods=["GET"])
def pending_transactions():
    return jsonify({
        "pending": [tx.to_dict() for tx in bc.pending_transactions],
        "count": len(bc.pending_transactions),
    })


# ─────────────────────────────────────────────
#  MINING ENDPOINT
# ─────────────────────────────────────────────

@app.route("/mine", methods=["POST"])
def mine():
    data = request.get_json()
    miner_address = data.get("miner_address") if data else None
    if not miner_address:
        return jsonify({"error": "miner_address required"}), 400

    if not bc.pending_transactions and len(bc.chain) > 1:
        return jsonify({"message": "No pending transactions to mine", "tip": "Add transactions first"}), 200

    start = time.time()
    block = bc.mine_pending_transactions(miner_address)
    elapsed = round(time.time() - start, 3)

    return jsonify({
        "message": "Block mined!",
        "block": block.to_dict(),
        "mining_time_seconds": elapsed,
        "miner_reward": 50.0,
        "new_balance": bc.get_balance(miner_address),
    }), 201


# ─────────────────────────────────────────────
#  CHAIN & EXPLORER ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/chain", methods=["GET"])
def full_chain():
    return jsonify({
        **bc.to_dict(),
        "length": len(bc.chain),
    })


@app.route("/chain/validate", methods=["GET"])
def validate_chain():
    valid, message = bc.is_chain_valid()
    return jsonify({
        "valid": valid,
        "message": message,
        "chain_length": len(bc.chain),
    })


@app.route("/block/<int:index>", methods=["GET"])
def get_block(index):
    if index < 0 or index >= len(bc.chain):
        return jsonify({"error": "Block not found"}), 404
    return jsonify({"block": bc.chain[index].to_dict()})


@app.route("/balance/<address>", methods=["GET"])
def get_balance(address):
    return jsonify({
        "address": address,
        "balance": bc.get_balance(address),
    })


@app.route("/stats", methods=["GET"])
def stats():
    all_balances = bc.get_all_balances()
    total_supply = sum(b for b in all_balances.values() if b > 0)
    total_txs = sum(len(b.transactions) for b in bc.chain)
    return jsonify({
        "blocks": len(bc.chain),
        "total_transactions": total_txs,
        "pending_transactions": len(bc.pending_transactions),
        "wallets": len(bc.wallets),
        "difficulty": 3,
        "mining_reward": 50.0,
        "total_supply_mined": total_supply,
    })


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🔗 PyChain Node starting on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
