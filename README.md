# PyChain — University Blockchain Project

A full-stack blockchain implementation with:
- RSA-2048 signed transactions
- Proof-of-Work mining (SHA-256)
- Block explorer & chain validator
- Wallet creation with keypairs
- REST API (Flask) + browser frontend

---

## Quick Start

### 1. Install dependencies
```bash
pip install flask flask-cors cryptography
```

### 2. Start the API server
```bash
python app.py
```
> API will run at http://localhost:5000

### 3. Open the frontend
Open `index.html` in your browser (just double-click it or use Live Server).

---

## File Structure

```
blockchain.py   – Core blockchain logic
  ├── Wallet       – RSA-2048 keypair, address derivation, signing
  ├── Transaction  – Signed transfers + COINBASE rewards
  ├── Block        – SHA-256 hashed block with PoW
  └── Blockchain   – Chain management, mining, validation

app.py          – Flask REST API
index.html      – Browser UI (no build step needed)
```

---

## API Endpoints

| Method | Endpoint              | Description                        |
|--------|-----------------------|------------------------------------|
| POST   | /wallet/new           | Generate RSA-2048 wallet           |
| GET    | /wallet/`<address>`   | Get wallet info + balance          |
| GET    | /wallets              | List all wallets                   |
| POST   | /transaction/new      | Broadcast a signed transaction     |
| GET    | /pending              | View pending transaction pool      |
| POST   | /mine                 | Mine pending txs (PoW)             |
| GET    | /chain                | Full blockchain                    |
| GET    | /chain/validate       | Validate chain integrity           |
| GET    | /block/`<index>`      | Get a single block                 |
| GET    | /balance/`<address>`  | Get address balance                |
| GET    | /stats                | Network statistics                 |

---

## How It Works

### Wallets
- RSA-2048 keypair generated via Python `cryptography` library
- Address = first 40 hex chars of SHA-256(public key), prefixed with `0x`
- Transactions signed with private key using PKCS1v15 + SHA-256

### Transactions
- Each transaction contains: sender, recipient, amount, timestamp, tx_id
- Sender signs a string of those fields with their private key
- Server verifies the signature before accepting into the mempool
- Insufficient balance = rejected

### Mining (Proof of Work)
- Pending transactions are bundled into a new block
- SHA-256 is run repeatedly (incrementing `nonce`) until hash starts with 3 zeros
- Miner receives 50 PYC COINBASE reward in the same block
- Block is appended to the chain once valid hash found

### Chain Validation
- Re-computes every block's hash and checks it matches stored value
- Verifies each block links to the previous via `previous_hash`
- Checks every non-coinbase transaction signature

---

## Example Flow (via UI)

1. **New Wallet** → Create 2 wallets (Alice, Bob)
2. **Mine Block** → Mine a block with Alice as miner → she gets 50 PYC
3. **Send Coins** → Alice sends 10 PYC to Bob (paste her private key)
4. **Mine Block** → Mine again to confirm the transaction
5. **Block Explorer** → See both blocks with their transactions
6. **Validate Chain** → Confirm integrity ✓

---

## Notes for University Submission

- This is a **simplified educational blockchain** — not production-grade
- Difficulty is set to 3 leading zeros (fast for demo; Bitcoin uses ~18)
- Wallets are stored in-memory (restart = fresh chain; add SQLite for persistence)
- Private keys are returned by the API for demo convenience only

## To add persistence (SQLite), replace the `Blockchain.__init__` with file I/O.
