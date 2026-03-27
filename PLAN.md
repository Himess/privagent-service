# PrivAgent Service — Implementation Plan

Privacy-as-a-Service API on Tempo MPP. Wraps PrivAgent's on-chain privacy infrastructure
(ShieldedPoolV4, JoinSplit ZK proofs, stealth addresses, encrypted notes) as paid endpoints
that AI agents and developers can consume via micropayments.

---

## 1. Context and Motivation

### What We Have

**ZKProver** (`zk-proof-service`) — Live at `himess-zk-proof-service.hf.space`
- Stateless Groth16 proof generation service on Tempo MPP
- Hono + mppx + snarkjs, deployed on HF Spaces (Docker)
- Endpoints: `/prove/1x2` ($0.01), `/prove/2x2` ($0.02), `/verify/:circuit` (free)
- Client sends raw circuit inputs, gets back proof + public signals
- No wallet state, no tree sync, no UTXO management

**PrivAgent** (`privagent`) — SDK + Contracts + Circuits on Base Sepolia
- Full privacy stack: ShieldedPoolV4 (JoinSplit UTXO), Groth16 circuits, stealth addresses
- SDK: ShieldedWallet, MerkleTree, NoteStore, coin selection, note encryption, view tags
- x402 integration: middleware (paywall), fetch wrapper, payment handler, facilitator, relayer
- Contracts: ShieldedPoolV4.sol, StealthRegistry.sol, PoseidonHasher.sol, Groth16 verifiers
- Circuits: joinSplit.circom (1x2, 2x2), merkleProof.circom
- Agent integrations: OpenClaw skill, Virtuals plugin, ERC-8004

### The Gap

ZKProver is stateless — it generates proofs from raw inputs but knows nothing about wallets,
UTXOs, Merkle trees, or the privacy pool. A developer who wants to make a private payment
must:

1. Initialize Poseidon
2. Generate a keypair
3. Sync the Merkle tree from on-chain events (paginated, 9K block chunks)
4. Track UTXOs in a NoteStore
5. Do coin selection
6. Build circuit inputs (extDataHash, nullifiers, commitments, Merkle proofs)
7. Generate a Groth16 proof (~3-5s)
8. Encrypt output notes (ECDH + AES-256-GCM)
9. Submit transact() on-chain
10. Update local UTXO state

PrivAgent Service wraps steps 1-10 as paid API calls. An agent pays $0.05 and says
"send 1 USDC privately to this pubkey" — the service handles everything.

---

## 2. Architecture

```
                      Tempo MPP (402 Payment)
                              |
Agent/Client  ------>  PrivAgent Service  ------> Base Sepolia
   HTTP POST           (Hono + mppx)              ShieldedPoolV4
   + MPP payment        |                          StealthRegistry
                        |--- ShieldedWallet (per-user, server-custodial)
                        |--- MerkleTree (synced from chain)
                        |--- NoteStore (encrypted, persistent)
                        |--- snarkjs (proof generation)
                        |--- ethers (on-chain submission)
```

### Key Architectural Decision: Server-Custodial vs Non-Custodial

**Option A: Server-Custodial (Recommended for MVP)**
- Service holds ShieldedWallet private keys (Poseidon keypair + ECDH keypair)
- Users get a `walletId` (API-managed), service stores encrypted notes
- Simpler UX: "deposit 10 USDC" / "transfer 5 USDC to pubkey X" / "check balance"
- Service pays gas for on-chain transactions (included in endpoint price)
- Risk: server is a custodian — mitigate with per-wallet encryption (FileNoteStore with HKDF)

**Option B: Non-Custodial (Proof Generation Only)**
- Client holds keys, sends pre-built circuit inputs (like ZKProver)
- Service only does proof generation + optional relay
- More like an enhanced ZKProver with tree sync and relay
- Less useful as a standalone service — client still needs most of the SDK

**Recommendation:** Start with Option A (custodial) for the demo and hackathon impact.
Add Option B endpoints for advanced users who want proof-only or relay-only. Both options
share the same infrastructure (tree sync, proof gen, relay). The custodial model is what
makes this a full "privacy-as-a-service" rather than just another prover.

---

## 3. Project Structure

```
privagent-service/
  src/
    server.ts           # Hono app, routes, MPP gating, OpenAPI, landing page
    wallet-manager.ts   # Multi-wallet management, creation, lookup
    pool-service.ts     # ShieldedPoolV4 interaction, tree sync, on-chain submission
    privacy-engine.ts   # Proof generation, coin selection, note encryption (wraps SDK)
    stealth.ts          # Stealth address generation and scanning
    note-store.ts       # Persistent encrypted NoteStore (FileNoteStore adapter)
    types.ts            # Request/response types, Zod schemas
    config.ts           # Environment variables, pool addresses, circuit paths
  circuits/             # Compiled circuit artifacts (wasm, zkey, vkey)
    1x2/
      joinSplit_1x2.wasm
      joinSplit_1x2_final.zkey
      verification_key.json
    2x2/
      joinSplit_2x2.wasm
      joinSplit_2x2_final.zkey
      verification_key.json
  wallets/              # Encrypted wallet data (gitignored)
  Dockerfile
  package.json
  tsconfig.json
  README.md             # HF Spaces metadata + docs
  .env.example
```

### Dependencies

```json
{
  "dependencies": {
    "@hono/node-server": "^1.19",
    "hono": "^4.12",
    "mppx": "^0.4.7",
    "snarkjs": "^0.7.6",
    "ethers": "^6.13",
    "circomlibjs": "^0.1.7",
    "@noble/curves": "^2.0",
    "@noble/hashes": "^2.0",
    "viem": "^2.47",
    "zod": "^4.3"
  }
}
```

Key difference from ZKProver: adds `ethers` (for on-chain interaction), `@noble/curves`
and `@noble/hashes` (for ECDH note encryption), and manages persistent state.

---

## 4. Endpoints

### Free Endpoints (No Payment)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Landing page (dark theme HTML) |
| GET | `/health` | Health check, pool status, tree height |
| GET | `/info` | Service capabilities, pricing, supported pools |
| GET | `/openapi.json` | OpenAPI 3.1 spec for MPPscan discovery |
| GET | `/llms.txt` | Agent discovery document |
| GET | `/.well-known/x402` | x402 discovery |
| GET | `/pool/status` | Pool balance, tree info, fee params |

### Paid Endpoints (MPP Gated)

| Method | Path | Cost | Description |
|--------|------|------|-------------|
| POST | `/wallet/create` | $0.01 | Create a new shielded wallet (returns walletId + pubkeys) |
| GET | `/wallet/:id/balance` | $0.005 | Get shielded balance (requires tree sync) |
| GET | `/wallet/:id/utxos` | $0.005 | List unspent UTXOs |
| POST | `/deposit` | $0.05 | Deposit USDC into shielded pool (proof gen + on-chain TX) |
| POST | `/transfer` | $0.05 | Private transfer between shielded wallets (proof gen + on-chain TX) |
| POST | `/withdraw` | $0.05 | Withdraw from shielded pool to public address (proof gen + TX) |
| POST | `/prove/:circuit` | $0.01 | Raw proof generation (like ZKProver, stateless) |
| POST | `/verify/:circuit` | Free | Verify a proof |
| POST | `/relay` | $0.02 | Submit a pre-built transact() call on-chain (gas included) |
| POST | `/stealth/generate` | $0.005 | Generate a stealth address for a recipient |
| POST | `/stealth/scan` | $0.01 | Scan for incoming stealth payments |
| POST | `/encrypt-note` | $0.005 | Encrypt a UTXO note (ECDH + AES-256-GCM) |
| POST | `/decrypt-note` | $0.005 | Decrypt an encrypted note |

### Pricing Rationale

- **Wallet create** ($0.01): One-time, generates keypairs + stores encrypted state. Cheap to encourage adoption.
- **Balance/UTXOs** ($0.005): Requires tree sync (RPC calls), but cached. Cheap to encourage polling.
- **Deposit/Transfer/Withdraw** ($0.05): The main product. Includes proof generation (~3-5s compute), on-chain TX submission (gas), tree sync, coin selection, note encryption. Service absorbs Base Sepolia gas (~$0.001). Premium over raw proof cost because it handles the full pipeline.
- **Raw prove** ($0.01): Same as ZKProver — backward compatible. Client brings their own inputs.
- **Relay** ($0.02): Client built the proof, service just submits on-chain. Cheaper than full pipeline.
- **Stealth/Encrypt** ($0.005): Lightweight crypto operations, mainly compute.

---

## 5. Endpoint Details

### POST /wallet/create

Creates a server-custodial shielded wallet.

**Request:**
```json
{
  "label": "my-agent-wallet"   // optional, for the user's reference
}
```

**Response:**
```json
{
  "walletId": "w_a1b2c3d4",
  "poseidonPubkey": "12345678901234567890...",
  "ecdhPublicKey": "0x04abc...",
  "createdAt": "2026-03-27T12:00:00Z"
}
```

**Implementation:**
1. Generate random Poseidon private key -> derive pubkey via `Poseidon(privKey)`
2. Generate random secp256k1 private key -> derive compressed public key
3. Create `ShieldedWallet` instance with `FileNoteStore` (encrypted with HKDF from privkey)
4. Store wallet metadata in `wallets/{walletId}.json` (encrypted)
5. Return public keys (never expose private keys)

**Security:** Wallet file encrypted at rest with AES-256-GCM. Encryption key derived from
wallet private key via HKDF. Server process holds keys in memory only while serving requests.

---

### POST /deposit

Deposits USDC from a public address into the shielded pool.

**Request:**
```json
{
  "walletId": "w_a1b2c3d4",
  "amount": "1000000",          // 1 USDC (6 decimals)
  "fromAddress": "0x..."        // optional, for USDC approval tracking
}
```

**Response:**
```json
{
  "success": true,
  "txHash": "0xabc...",
  "blockNumber": 12345,
  "commitment": "98765...",
  "leafIndex": 42,
  "shieldedBalance": "990000",  // after protocol fee
  "protocolFee": "10000",
  "proofTimeMs": 4200
}
```

**Implementation:**
1. Load wallet from NoteStore
2. Sync Merkle tree from on-chain events
3. Calculate protocol fee (query pool contract)
4. Create deposit UTXO + dummy output
5. Generate Groth16 proof (1x2 circuit)
6. Approve USDC + call `pool.transact()`
7. Update local NoteStore with new UTXO
8. Return TX hash + updated balance

**Challenge:** The service's server wallet must hold USDC to deposit. Two options:
- **Option 1:** Service wallet deposits on behalf of user (service must be funded)
- **Option 2:** User pre-approves USDC to pool, service just generates proof + submits TX

For MVP, use Option 1 with a service-funded wallet. The $0.05 endpoint price covers gas.
For production, add an approval flow where users approve USDC from their own wallet,
and the service submits the transaction.

---

### POST /transfer

Private transfer between shielded wallets. Amount stays hidden on-chain.

**Request:**
```json
{
  "walletId": "w_a1b2c3d4",
  "amount": "500000",           // 0.5 USDC
  "recipientPubkey": "12345...", // Poseidon pubkey of recipient
  "recipientEcdhPubkey": "0x04..." // secp256k1 pubkey for note encryption
}
```

**Response:**
```json
{
  "success": true,
  "txHash": "0xdef...",
  "blockNumber": 12350,
  "nullifiers": ["111...", "222..."],
  "commitments": ["333...", "444..."],
  "remainingBalance": "490000",
  "proofTimeMs": 5100
}
```

**Implementation:**
1. Load wallet, sync tree
2. Coin selection (selectUTXOs) to cover amount + protocol fee
3. Create payment UTXO (to recipient) + change UTXO (to self)
4. Encrypt both output notes (ECDH with respective pubkeys)
5. Compute extDataHash
6. Generate Groth16 proof (1x2 or 2x2 depending on inputs needed)
7. Submit `pool.transact()` with publicAmount=0 (private transfer)
8. Mark spent UTXOs, add new UTXOs to NoteStore
9. Return result

---

### POST /withdraw

Withdraw from shielded pool to a public Ethereum address.

**Request:**
```json
{
  "walletId": "w_a1b2c3d4",
  "amount": "500000",
  "recipientAddress": "0x742d35..."
}
```

**Response:**
```json
{
  "success": true,
  "txHash": "0xghi...",
  "blockNumber": 12355,
  "withdrawnAmount": "500000",
  "recipientAddress": "0x742d35...",
  "remainingBalance": "0",
  "proofTimeMs": 4800
}
```

**Implementation:** Similar to transfer, but with `publicAmount = -(amount + fee)` and
`recipient = withdrawAddress`. The pool contract sends USDC to the recipient publicly.

---

### POST /relay

Submit a pre-built transaction on-chain. For clients who generated their own proof
(e.g., using ZKProver + their own tree/wallet) but want gas-free submission.

**Request:**
```json
{
  "args": {
    "pA": ["...", "..."],
    "pB": [["...","..."],["...","..."]],
    "pC": ["...", "..."],
    "root": "0x...",
    "publicAmount": "0",
    "extDataHash": "0x...",
    "protocolFee": "10000",
    "inputNullifiers": ["0x..."],
    "outputCommitments": ["0x...", "0x..."],
    "viewTags": [42, 128]
  },
  "extData": {
    "recipient": "0x0000000000000000000000000000000000000000",
    "relayer": "0x0000000000000000000000000000000000000000",
    "fee": "0",
    "encryptedOutput1": "0xaa...",
    "encryptedOutput2": "0xbb..."
  }
}
```

**Response:**
```json
{
  "success": true,
  "txHash": "0x...",
  "blockNumber": 12360,
  "gasUsed": "245000"
}
```

**Implementation:**
1. Optional: off-chain proof verification (snarkjs) to prevent gas griefing
2. Gas estimation via `pool.transact.estimateGas()`
3. Submit `pool.transact()` with 20% gas buffer
4. Return receipt

---

## 6. State Management

### Merkle Tree Sync

The service must maintain a local copy of the on-chain Merkle tree. This is the most
expensive operation (scans `NewCommitment` events from deploy block).

**Strategy:**
- Sync on startup, then periodically (every 30 seconds)
- Cache the tree in memory (MerkleTree class from SDK)
- Store the last synced block number to avoid re-scanning from genesis
- Use the existing `syncTreeFromEvents()` function from `sdk/src/v4/treeSync.ts`
- Single shared tree instance for all wallets (the tree is global to the pool)

**Estimated sync time:** Depends on pool activity. On fresh Base Sepolia pool, ~1-2s.
On busy pool with 10K leaves, ~10-30s (paginated 9K block chunks).

### NoteStore (Per Wallet)

Each wallet has its own encrypted NoteStore (FileNoteStore from SDK).

**Storage layout:**
```
wallets/
  w_a1b2c3d4/
    meta.json.enc       # Encrypted wallet metadata (pubkeys, creation time)
    notes.json.enc      # Encrypted UTXO notes (AES-256-GCM, HKDF from privkey)
  w_e5f6g7h8/
    meta.json.enc
    notes.json.enc
```

**Data volume:** Each note is ~200 bytes JSON. A wallet with 100 notes = ~20KB.
Even 10,000 wallets with 100 notes each = 200MB total. Well within HF Spaces limits.

### In-Memory State

- `Map<walletId, ShieldedWallet>` — loaded on demand, evicted after 5 min idle
- Single `MerkleTree` instance — shared across all wallets
- `Map<nullifier, boolean>` — pending nullifier mutex (like in middleware)

---

## 7. What Reuses from ZKProver vs What's New

### Direct Reuse from ZKProver

| Component | ZKProver | PrivAgent Service |
|-----------|----------|-------------------|
| Framework | Hono + cors | Same |
| Payment gating | mppx (Tempo MPP) | Same |
| Proof generation | snarkjs.groth16.fullProve | Same |
| Proof verification | snarkjs.groth16.verify | Same |
| Circuit artifacts | circuits/1x2, circuits/2x2 | Same files |
| Landing page | HTML in server.ts | Same pattern |
| Discovery | /llms.txt, /openapi.json, /.well-known/x402 | Same pattern |
| Docker deploy | node:22-slim, HF Spaces | Same |
| x402 schema middleware | withX402Schema() | Same pattern |

### New from PrivAgent SDK

| Component | Source | Notes |
|-----------|--------|-------|
| ShieldedWallet | sdk/src/v4/shieldedWallet.ts | Core wallet logic |
| MerkleTree | sdk/src/merkle.ts | Poseidon-based, depth 20 |
| NoteStore | sdk/src/v4/noteStore.ts | FileNoteStore with AES-256-GCM |
| Coin selection | sdk/src/v4/coinSelection.ts | Exact match, then smallest-first |
| Note encryption | sdk/src/v4/noteEncryption.ts | ECDH + AES-256-GCM |
| UTXO types | sdk/src/v4/utxo.ts | Create, serialize, dummy |
| Keypair | sdk/src/v4/keypair.ts | Poseidon-based |
| ExtData | sdk/src/v4/extData.ts | Hash matching on-chain |
| View tags | sdk/src/v4/viewTag.ts | Scan optimization |
| Tree sync | sdk/src/v4/treeSync.ts | On-chain event scanning |
| Poseidon | sdk/src/poseidon.ts | circomlibjs wrapper |

### Approach: Inline the SDK

Rather than importing `privagent-sdk` as an npm dependency (it's not published),
inline the relevant source files directly into the service. The V4 engine is ~10 files,
all pure TypeScript with minimal dependencies (ethers, snarkjs, @noble/curves, circomlibjs).

Copy these files into `src/privagent/`:
```
src/privagent/
  poseidon.ts
  merkle.ts
  types.ts
  v4/
    utxo.ts
    keypair.ts
    coinSelection.ts
    joinSplitProver.ts
    extData.ts
    noteEncryption.ts
    noteStore.ts
    treeSync.ts
    viewTag.ts
    signalIndex.ts
    shieldedWallet.ts
```

This avoids dependency management issues and lets us modify the SDK code for
service-specific needs (e.g., shared tree instance, custom NoteStore backend).

---

## 8. Technical Challenges and Solutions

### Challenge 1: Proof Generation Time (~3-5s)

snarkjs Groth16 proof generation takes 3-5 seconds per proof. For high-level endpoints
(deposit/transfer/withdraw), this is the bottleneck.

**Solution:**
- Accept the latency — 5s is fine for a payment operation
- Return proof time in response for transparency
- Consider a queue + webhook pattern for async proof generation (v2)
- HF Spaces has 16GB RAM — sufficient for parallel proofs (each ~200MB peak)
- Limit concurrent proof generation to 2-3 to avoid OOM

### Challenge 2: Tree Sync on Cold Start

First request after deploy must sync the entire Merkle tree from chain events.

**Solution:**
- Sync tree on server startup (before accepting requests)
- Persist last synced block number in a file (`tree-state.json`)
- On restart, only sync from last known block
- Background sync every 30 seconds
- Return 503 if tree is not yet synced

### Challenge 3: Server Wallet Funding

The service wallet needs ETH (for gas) and USDC (for deposits) on Base Sepolia.

**Solution:**
- For testnet: pre-fund the service wallet from a faucet
- Use `tempo_fundAddress` RPC for Tempo chain gas (same as ZKProver)
- For deposit endpoint: require users to pre-approve USDC to the pool contract,
  then the service just submits the proof. Service wallet only pays gas (~$0.001).
- Gas cost is negligible on Base Sepolia — the $0.05 endpoint price covers it easily.

### Challenge 4: Wallet Key Security

Server holds private keys for custodial wallets.

**Solution:**
- Encrypt wallet files at rest with AES-256-GCM (FileNoteStore already does this)
- HKDF key derivation from wallet private key — no separate encryption key to manage
- Environment variable for master encryption key (encrypts wallet private keys themselves)
- Never log or return private keys in responses
- For production: use KMS (AWS KMS, GCP KMS) — out of scope for hackathon

### Challenge 5: Concurrent Wallet Access

Multiple requests to the same wallet could cause race conditions (double-spend).

**Solution:**
- Per-wallet mutex (simple Map<walletId, Promise>) — serialize requests per wallet
- UTXO pending lock (already in ShieldedWallet — `utxo.pending = true`)
- Nullifier mutex (already in middleware — `pendingNullifiers` Set)

### Challenge 6: Circuit Artifacts Size

The wasm + zkey files are ~15-20MB per circuit. With 2 circuits, that's ~40MB.

**Solution:**
- Include in Docker image (same as ZKProver)
- Docker image will be ~200MB total — acceptable for HF Spaces
- Reuse the same circuit artifacts from ZKProver (they're identical)

### Challenge 7: RPC Rate Limits

Tree sync makes many RPC calls (one per 9K block chunk).

**Solution:**
- Use a reliable RPC provider (Alchemy, Infura, or Base's public RPC)
- Cache tree state — only sync delta blocks
- Rate limit tree sync to once per 30 seconds
- Environment variable for RPC URL

---

## 9. Composability with ZKProver

PrivAgent Service and ZKProver are complementary:

```
Agent wants private payment
  |
  v
[PrivAgent Service] /transfer  ($0.05)
  |--- Uses ZKProver internally (or inline snarkjs)
  |--- Handles wallet, tree, UTXO, encryption, submission
  |
  v
Transaction confirmed on Base Sepolia

---

Advanced agent builds own proof
  |
  v
[ZKProver] /prove/1x2  ($0.01)    <-- just proof generation
  |
  v
[PrivAgent Service] /relay  ($0.02)  <-- on-chain submission
  |
  v
Transaction confirmed
```

The compose-privacy demo (`zk-proof-service/src/compose-privacy.ts`) already shows
this pattern: Dossier (compliance) -> ZKProver (proof) -> verify. PrivAgent Service
adds a third composable service to the ecosystem.

---

## 10. Implementation Order

### Phase 1: Core Infrastructure (Day 1)

1. **Project scaffolding** — package.json, tsconfig, Dockerfile, .env.example
2. **Copy circuit artifacts** from ZKProver
3. **Inline PrivAgent SDK** — copy V4 engine files into src/privagent/
4. **Config module** — env vars, pool address, RPC URL, wallet paths
5. **Server skeleton** — Hono app, CORS, landing page, health, info
6. **MPP gating** — mppx setup (reuse ZKProver pattern exactly)
7. **Proof generation** — `/prove/:circuit` endpoint (copy from ZKProver)
8. **Verification** — `/verify/:circuit` endpoint (copy from ZKProver)

### Phase 2: Privacy Engine (Day 1-2)

9. **Poseidon init** — lazy-init on first request
10. **Tree sync** — startup + periodic background sync
11. **Pool service** — connect to ShieldedPoolV4, query state
12. **Wallet manager** — create, load, list wallets
13. **NoteStore adapter** — FileNoteStore with encrypted persistence

### Phase 3: High-Level Endpoints (Day 2)

14. **POST /wallet/create** — keypair generation, store encrypted
15. **GET /wallet/:id/balance** — load wallet, compute from UTXOs
16. **POST /deposit** — full pipeline (proof gen + on-chain TX)
17. **POST /transfer** — full pipeline (coin selection + proof + TX)
18. **POST /withdraw** — full pipeline (proof + public withdrawal TX)
19. **POST /relay** — accept pre-built args, submit on-chain

### Phase 4: Advanced Features (Day 2-3)

20. **Stealth endpoints** — generate/scan stealth addresses
21. **Encrypt/decrypt note** — ECDH note encryption endpoints
22. **GET /wallet/:id/utxos** — detailed UTXO listing
23. **GET /pool/status** — pool balance, tree height, fee params

### Phase 5: Discovery and Deploy (Day 3)

24. **OpenAPI spec** — full spec with all endpoints, x-payment-info, bazaar schemas
25. **llms.txt** — agent discovery document
26. **x402 discovery** — .well-known/x402
27. **x402 schema middleware** — withX402Schema for all paid endpoints
28. **Docker build and test**
29. **Deploy to HF Spaces**
30. **Demo script** — compose PrivAgent Service + ZKProver + Dossier

---

## 11. Environment Variables

```env
# Server
PORT=7860

# Tempo MPP
MPP_SECRET_KEY=your-mpp-secret-key
SERVER_PRIVATE_KEY=0x...          # Tempo wallet for MPP

# Base Sepolia
BASE_SEPOLIA_RPC=https://sepolia.base.org
RELAYER_PRIVATE_KEY=0x...         # Wallet that pays gas for on-chain TXs

# Pool contract
POOL_ADDRESS=0x...                # ShieldedPoolV4 on Base Sepolia
USDC_ADDRESS=0x036CbD53842c5426634e7929541eC2318f3dCF7e  # Base Sepolia USDC
POOL_DEPLOY_BLOCK=0               # Block number to start tree sync from

# Wallet storage
WALLET_DIR=./wallets
MASTER_KEY=your-master-encryption-key  # Encrypts wallet private keys

# Optional
TREE_SYNC_INTERVAL_MS=30000
MAX_CONCURRENT_PROOFS=2
```

---

## 12. Deployment

Same as ZKProver: Docker on Hugging Face Spaces.

```dockerfile
FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY src/ ./src/
COPY circuits/ ./circuits/

# Wallet storage directory (persistent volume on HF Spaces)
RUN mkdir -p /app/wallets

ENV PORT=7860
EXPOSE 7860

CMD ["npx", "tsx", "src/server.ts"]
```

**HF Spaces config** (in README.md frontmatter):
```yaml
---
title: PrivAgent Service
emoji: 🛡
colorFrom: purple
colorTo: blue
sdk: docker
app_port: 7860
---
```

---

## 13. Demo Script

```bash
# 1. Check service health
tempo request -t https://himess-privagent-service.hf.space/health

# 2. See pricing and capabilities
tempo request -t https://himess-privagent-service.hf.space/info

# 3. Create a shielded wallet ($0.01)
tempo request -X POST \
  -H "Content-Type: application/json" \
  --json '{"label":"demo-wallet"}' \
  https://himess-privagent-service.hf.space/wallet/create

# 4. Check pool status (free)
tempo request -t https://himess-privagent-service.hf.space/pool/status

# 5. Generate a raw proof ($0.01) — backward compatible with ZKProver
tempo request -X POST \
  -H "Content-Type: application/json" \
  -d @input.json \
  https://himess-privagent-service.hf.space/prove/1x2

# 6. Compose: Compliance check + Private transfer
# (same pattern as compose-privacy.ts but with PrivAgent Service)
```

### 2-Minute Demo Narrative

1. **"Here's the problem"** — Agents need privacy but the privacy stack is complex
   (tree sync, UTXO management, proof generation, on-chain submission)
2. **Show health + info** — Service is live, here's what it can do
3. **Create wallet** — $0.01 payment, get back pubkeys
4. **Show proof generation** — $0.01, same as ZKProver but now with more context
5. **Explain the full pipeline** — deposit/transfer/withdraw handle everything
6. **Composability** — ZKProver for proofs, PrivAgent Service for full privacy,
   Dossier for compliance — three MPP services, one autonomous agent

---

## 14. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Proof generation OOM on HF Spaces | Low | High | Limit concurrent proofs to 2, use 16GB RAM tier |
| RPC rate limiting during tree sync | Medium | Medium | Cache aggressively, sync only deltas |
| Wallet key compromise | Low | Critical | At-rest encryption, env-based master key |
| Pool contract not deployed | Low | Critical | Pre-deploy before hackathon, hardcode address |
| Long cold start (tree sync) | Medium | Low | Persist tree state, sync on startup |
| Base Sepolia downtime | Low | High | Return 503, graceful degradation |
| USDC funding for deposits | Medium | Medium | Pre-fund service wallet, or require user approval |

---

## 15. Success Criteria

For the hackathon demo:

1. Service is live on HF Spaces
2. At least 3 paid endpoints working (wallet/create, prove, relay)
3. Full deposit -> transfer -> withdraw pipeline working end-to-end
4. Compose demo: PrivAgent Service + ZKProver chained
5. Agent-discoverable: llms.txt, OpenAPI, x402
6. Clean landing page with endpoint table and "Try it" section

---

## 16. Future Enhancements (Post-Hackathon)

- **Non-custodial mode:** Client-side proof generation, server just relays
- **Stealth address resolution:** Integrate with StealthRegistry contract
- **Batch operations:** Multiple transfers in one proof (2x2 circuit)
- **WebSocket subscriptions:** Real-time UTXO updates
- **Multi-pool support:** Multiple ShieldedPoolV4 instances
- **Proof of Innocence:** V4.5 compliance integration
- **Production deployment:** Railway/Fly.io with persistent volumes + KMS
- **SDK client:** TypeScript client library for PrivAgent Service
- **ERC-8004 integration:** Agent registration with privacy payment method
