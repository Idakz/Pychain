import hashlib
import json
import time
import uuid
import sqlite3
import os
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

DB_PATH = "pychain.db"

# ─────────────────────────────────────────────
#  DATABASE SETUP
# ─────────────────────────────────────────────

def get_db():
    """Return a database connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_db()
    c = conn.cursor()

    # Wallets table — stores address, public key, private key
    c.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            address     TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at  REAL NOT NULL
        )
    """)

    # Blocks table — one row per block
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            idx           INTEGER PRIMARY KEY,
            hash          TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            nonce         INTEGER NOT NULL,
            timestamp     REAL NOT NULL
        )
    """)

    # Transactions table — one row per transaction, linked to a block
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id      TEXT PRIMARY KEY,
            block_idx  INTEGER,              -- NULL = pending
            sender     TEXT NOT NULL,
            recipient  TEXT NOT NULL,
            amount     REAL NOT NULL,
            timestamp  REAL NOT NULL,
            public_key TEXT,
            signature  TEXT,
            FOREIGN KEY (block_idx) REFERENCES blocks(idx)
        )
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
#  WALLET
# ─────────────────────────────────────────────

class Wallet:
    """RSA-2048 keypair wallet. Signs transactions with private key."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.address = self._derive_address()

    def _derive_address(self) -> str:
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha256(pub_bytes).hexdigest()
        return "0x" + digest[:40]

    def sign(self, message: str) -> str:
        signature = self.private_key.sign(
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def export_public_key(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def export_private_key(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "public_key": self.export_public_key(),
            "private_key": self.export_private_key(),
        }


def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, message.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, Exception):
        return False


# ─────────────────────────────────────────────
#  TRANSACTION
# ─────────────────────────────────────────────

class Transaction:
    def __init__(self, sender: str, recipient: str, amount: float,
                 public_key: str = "", signature: str = "",
                 tx_id: str = None, timestamp: float = None):
        self.tx_id = tx_id or str(uuid.uuid4())
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp or time.time()
        self.public_key = public_key
        self.signature = signature

    def to_signable_string(self) -> str:
        return f"{self.sender}{self.recipient}{self.amount}{self.timestamp}{self.tx_id}"

    def is_valid(self) -> bool:
        if self.sender == "COINBASE":
            return self.amount > 0
        if not self.public_key or not self.signature:
            return False
        return verify_signature(self.public_key, self.to_signable_string(), self.signature)

    def to_dict(self) -> dict:
        return {
            "tx_id": self.tx_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        return cls(
            sender=d["sender"],
            recipient=d["recipient"],
            amount=d["amount"],
            public_key=d.get("public_key", ""),
            signature=d.get("signature", ""),
            tx_id=d.get("tx_id"),
            timestamp=d.get("timestamp"),
        )

    @classmethod
    def from_row(cls, row) -> "Transaction":
        return cls(
            sender=row["sender"],
            recipient=row["recipient"],
            amount=row["amount"],
            public_key=row["public_key"] or "",
            signature=row["signature"] or "",
            tx_id=row["tx_id"],
            timestamp=row["timestamp"],
        )


# ─────────────────────────────────────────────
#  BLOCK
# ─────────────────────────────────────────────

class Block:
    def __init__(self, index: int, transactions: List[Transaction],
                 previous_hash: str, nonce: int = 0, timestamp: float = None):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.timestamp = timestamp or time.time()
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_str = json.dumps({
            "index": self.index,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "hash": self.hash,
        }


# ─────────────────────────────────────────────
#  BLOCKCHAIN
# ─────────────────────────────────────────────

MINING_REWARD = 50.0
MINING_DIFFICULTY = 3


class Blockchain:
    def __init__(self):
        init_db()
        self._load_or_create_genesis()

    # ── Internal DB helpers ───────────────────

    def _save_block(self, block: Block, conn):
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO blocks (idx, hash, previous_hash, nonce, timestamp) VALUES (?,?,?,?,?)",
            (block.index, block.hash, block.previous_hash, block.nonce, block.timestamp)
        )
        for tx in block.transactions:
            c.execute("""
                INSERT OR IGNORE INTO transactions
                (tx_id, block_idx, sender, recipient, amount, timestamp, public_key, signature)
                VALUES (?,?,?,?,?,?,?,?)
            """, (tx.tx_id, block.index, tx.sender, tx.recipient,
                  tx.amount, tx.timestamp, tx.public_key, tx.signature))

    def _load_block(self, row, conn) -> Block:
        c = conn.cursor()
        c.execute("SELECT * FROM transactions WHERE block_idx=? ORDER BY timestamp", (row["idx"],))
        txs = [Transaction.from_row(r) for r in c.fetchall()]
        block = Block(
            index=row["idx"],
            transactions=txs,
            previous_hash=row["previous_hash"],
            nonce=row["nonce"],
            timestamp=row["timestamp"],
        )
        block.hash = row["hash"]
        return block

    # ── Genesis ───────────────────────────────

    def _load_or_create_genesis(self):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as cnt FROM blocks")
        if c.fetchone()["cnt"] == 0:
            genesis = Block(index=0, transactions=[], previous_hash="0" * 64, nonce=0)
            genesis.hash = genesis.compute_hash()
            self._save_block(genesis, conn)
            conn.commit()
        conn.close()

    # ── Chain (loaded fresh from DB each time) ─

    @property
    def chain(self) -> List[Block]:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM blocks ORDER BY idx")
        blocks = [self._load_block(row, conn) for row in c.fetchall()]
        conn.close()
        return blocks

    @property
    def last_block(self) -> Block:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1")
        row = c.fetchone()
        block = self._load_block(row, conn)
        conn.close()
        return block

    @property
    def pending_transactions(self) -> List[Transaction]:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM transactions WHERE block_idx IS NULL ORDER BY timestamp")
        txs = [Transaction.from_row(r) for r in c.fetchall()]
        conn.close()
        return txs

    # ── Proof of Work ─────────────────────────

    def proof_of_work(self, block: Block) -> Block:
        target = "0" * MINING_DIFFICULTY
        block.nonce = 0
        block.hash = block.compute_hash()
        while not block.hash.startswith(target):
            block.nonce += 1
            block.hash = block.compute_hash()
        return block

    # ── Mining ────────────────────────────────

    def mine_pending_transactions(self, miner_address: str) -> Block:
        pending = self.pending_transactions
        reward_tx = Transaction(sender="COINBASE", recipient=miner_address, amount=MINING_REWARD)
        txs = pending + [reward_tx]

        last = self.last_block
        new_block = Block(index=last.index + 1, transactions=txs, previous_hash=last.hash)
        new_block = self.proof_of_work(new_block)

        conn = get_db()
        c = conn.cursor()
        self._save_block(new_block, conn)
        # Mark pending txs as confirmed in this block
        for tx in pending:
            c.execute("UPDATE transactions SET block_idx=? WHERE tx_id=?", (new_block.index, tx.tx_id))
        conn.commit()
        conn.close()
        return new_block

    # ── Transactions ──────────────────────────

    def add_transaction(self, tx: Transaction) -> bool:
        if not tx.is_valid():
            return False
        if tx.sender != "COINBASE" and self.get_balance(tx.sender) < tx.amount:
            return False
        conn = get_db()
        conn.execute("""
            INSERT INTO transactions
            (tx_id, block_idx, sender, recipient, amount, timestamp, public_key, signature)
            VALUES (?,NULL,?,?,?,?,?,?)
        """, (tx.tx_id, tx.sender, tx.recipient, tx.amount,
              tx.timestamp, tx.public_key, tx.signature))
        conn.commit()
        conn.close()
        return True

    # ── Balances ──────────────────────────────

    def get_balance(self, address: str) -> float:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT SUM(amount) as total FROM transactions WHERE recipient=? AND block_idx IS NOT NULL", (address,))
        received = c.fetchone()["total"] or 0.0
        c.execute("SELECT SUM(amount) as total FROM transactions WHERE sender=? AND block_idx IS NOT NULL", (address,))
        sent = c.fetchone()["total"] or 0.0
        conn.close()
        return round(received - sent, 8)

    def get_all_balances(self) -> Dict[str, float]:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT address FROM (
                SELECT DISTINCT recipient as address FROM transactions WHERE block_idx IS NOT NULL
                UNION
                SELECT DISTINCT sender as address FROM transactions WHERE block_idx IS NOT NULL AND sender != 'COINBASE'
            )
        """)
        addresses = [r["address"] for r in c.fetchall()]
        conn.close()
        return {addr: self.get_balance(addr) for addr in addresses}

    # ── Validation ────────────────────────────

    def is_chain_valid(self) -> tuple[bool, str]:
        target = "0" * MINING_DIFFICULTY
        chain = self.chain
        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i - 1]
            if current.hash != current.compute_hash():
                return False, f"Block {i} hash is invalid (tampered data)"
            if current.previous_hash != previous.hash:
                return False, f"Block {i} is not linked to block {i-1}"
            if not current.hash.startswith(target):
                return False, f"Block {i} fails proof-of-work check"
            for tx in current.transactions:
                if not tx.is_valid():
                    return False, f"Block {i} contains invalid transaction {tx.tx_id}"
        return True, "Chain is valid"

    # ── Wallets ───────────────────────────────

    def register_wallet(self, wallet_dict: dict):
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO wallets (address, public_key, private_key, created_at) VALUES (?,?,?,?)",
            (wallet_dict["address"], wallet_dict["public_key"], wallet_dict["private_key"], time.time())
        )
        conn.commit()
        conn.close()

    def get_wallet(self, address: str) -> Optional[dict]:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM wallets WHERE address=?", (address,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {"address": row["address"], "public_key": row["public_key"], "private_key": row["private_key"]}

    @property
    def wallets(self) -> Dict[str, dict]:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM wallets")
        rows = c.fetchall()
        conn.close()
        return {r["address"]: {"address": r["address"], "public_key": r["public_key"], "private_key": r["private_key"]} for r in rows}

    # ── Serialization ─────────────────────────

    def to_dict(self) -> dict:
        return {
            "chain": [b.to_dict() for b in self.chain],
            "pending_transactions": [tx.to_dict() for tx in self.pending_transactions],
            "difficulty": MINING_DIFFICULTY,
            "mining_reward": MINING_REWARD,
        }
