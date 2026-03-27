# PrivAgent Technical Research

Comprehensive analysis of https://github.com/Himess/privagent (master branch, March 2026).

---

## 1. Project Overview

PrivAgent is a **privacy layer for x402 payments on Base**, built around a ZK-UTXO model with Groth16 proofs. It hides payment amounts, senders, and recipients on-chain while remaining compatible with the x402 HTTP payment protocol and ERC-8004 agent identity standard.

- **Stack**: TypeScript SDK (privagent-sdk on npm), Solidity 0.8.24, Circom 2.0 circuits, Foundry, pnpm monorepo
- **Chain**: Base Sepolia (testnet), targeting Base mainnet
- **Token**: USDC only (6 decimals)
- **License**: BUSL-1.1 (converts to GPL-2.0 on March 1, 2028)

### Deployed Contracts (Base Sepolia)

| Contract | Address |
|----------|---------|
| ShieldedPoolV4 | `0x8F1ae8209156C22dFD972352A415880040fB0b0c` |
| Groth16Verifier_1x2 | `0xC53c8E05661450919951f51E4da829a3AABD76A2` |
| Groth16Verifier_2x2 | `0xE77ad940291c97Ae4dC43a6b9Ffb43a3AdCd4769` |
| PoseidonHasher | `0x70Aa742C113218a12A6582f60155c2B299551A43` |
| USDC (Base Sepolia) | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |

Deploy block: `38347380`

---

## 2. Architecture Deep Dive

### 2.1 UTXO Model

The core data structure is a UTXO (Unspent Transaction Output):

```typescript
interface UTXO {
  amount: bigint;      // token amount (hidden on-chain)
  pubkey: bigint;      // Poseidon(privateKey) - owner's public key
  blinding: bigint;    // random field element for commitment uniqueness
  commitment: bigint;  // Poseidon(amount, pubkey, blinding) - stored on-chain
  nullifier?: bigint;  // Poseidon(commitment, leafIndex, privateKey) - spent marker
  leafIndex?: number;  // position in Merkle tree
  spent: boolean;
  pending: boolean;    // lock for concurrent access
}
```

- **Commitment** = `Poseidon(amount, pubkey, blinding)` -- published on-chain, hides all values
- **Nullifier** = `Poseidon(commitment, leafIndex, privateKey)` -- published when spent, prevents double-spend
- **Keypair**: `publicKey = Poseidon(privateKey)` (BN254 field, NOT Ethereum address)

### 2.2 Circuit Architecture

Two Circom circuits, both using the JoinSplit pattern (Tornado Nova-derived):

| Circuit | Inputs | Outputs | Public Signals |
|---------|--------|---------|----------------|
| **1x2** | 1 input UTXO | 2 output UTXOs | 7 signals |
| **2x2** | 2 input UTXOs | 2 output UTXOs | 8 signals |

**Public signals layout** (order matters for verifier):
```
[0] root              - Merkle tree root
[1] publicAmount      - deposit/withdraw amount (0 for transfers)
[2] extDataHash       - hash binding external data (recipient, relayer, fee, encrypted notes)
[3] protocolFee       - circuit-enforced protocol fee
[4..4+nIns-1]         - input nullifiers
[4+nIns..4+nIns+nOuts-1] - output commitments
```

**Balance conservation constraint** (enforced in circuit):
```
sum(inputAmounts) + publicAmount === sum(outputAmounts) + protocolFee
```

**Key circuit features**:
- Poseidon hashing throughout (BN254-friendly)
- Merkle tree depth 20 (1M leaves max)
- 120-bit range checks on all amounts
- Duplicate nullifier check within circuit
- extDataHash quadratic constraint to bind proof to specific transaction params
- `ForceEqualIfEnabled` pattern for conditional root check (allows dummy inputs with amount=0)

### 2.3 On-Chain Contract: ShieldedPoolV4

Single entry point: `transact()` handles ALL operations (deposit, transfer, withdraw).

```solidity
function transact(TransactArgs calldata args, ExtData calldata extData) external
```

**TransactArgs**:
- `pA`, `pB`, `pC` -- Groth16 proof components
- `root` -- Merkle root (must be in recent 100 roots)
- `publicAmount` -- int256: >0 deposit, <0 withdraw, 0 transfer
- `extDataHash` -- binding hash
- `protocolFee` -- circuit-enforced fee
- `inputNullifiers[]` -- spent markers
- `outputCommitments[]` -- new UTXO commitments
- `viewTags[]` -- 1-byte per output for efficient note scanning

**ExtData**:
- `recipient` -- address (for withdrawals, zero for transfers)
- `relayer` -- address (fee recipient for gas)
- `fee` -- uint256 relayer fee
- `encryptedOutput1`, `encryptedOutput2` -- ECDH-encrypted UTXO data

**On-chain flow**:
1. Validate extDataHash matches hash of ExtData
2. Validate nullifiers (field range, uniqueness within tx, not previously used)
3. Validate Merkle root is in recent history (ring buffer of 100)
4. Validate view tags count
5. Validate protocol fee meets minimum
6. Select verifier by circuit config key (nIns * 256 + nOuts)
7. Verify Groth16 proof against public signals
8. Mark nullifiers as spent
9. Insert output commitments into Merkle tree, emit NewCommitment events
10. Handle token transfers based on publicAmount sign

**Protocol fee**: max(0.1% of amount, $0.01 USDC). Enforced in circuit AND contract.

### 2.4 Note Encryption (ECDH + AES-256-GCM)

Notes are encrypted so only the intended recipient can read them:

1. **ECDH**: secp256k1 shared secret between sender and receiver
2. **KDF**: HKDF-SHA256 with domain separation ("privagent-v4-note-encryption")
3. **Encryption**: AES-256-GCM
4. **Plaintext**: amount (8 bytes) + pubkey (32 bytes) + blinding (32 bytes) = 72 bytes
5. **Ciphertext**: iv (12) + tag (16) + encrypted (72) = 100 bytes

### 2.5 View Tags

1-byte Poseidon-based tags for 50x note scanning optimization. Generated from:
`Poseidon(senderPrivKey, recipientPubkey, nonce) & 0xFF`

Recipient can quickly filter out irrelevant notes before attempting decryption.

---

## 3. SDK API Surface

### 3.1 Main Export: `privagent-sdk`

```typescript
// Core
export { initPoseidon, hash1, hash2, hash3, computeCommitment, computeNullifierHash }
export { MerkleTree }

// V4 UTXO Engine
export { ShieldedWallet, ShieldedWalletConfig, TransactResult, GenerateTransactProofResult }
export { UTXO, createUTXO, createDummyUTXO, computeNullifierV4, computeCommitmentV4, derivePublicKey }
export { Keypair, generateKeypair, keypairFromPrivateKey }
export { selectUTXOs, getAvailableBalance }
export { generateJoinSplitProof, proofToArray }
export { ExtData, computeExtDataHash }
export { encryptNote, decryptNote }
export { syncTreeFromEvents, getSpentNullifiers }
export { NoteStore, MemoryNoteStore, FileNoteStore }
export { generateViewTag, checkViewTag }

// ERC-8004
export { privAgentPaymentMethod, paymentProofForFeedback }

// Utilities
export { createLogger, setLogLevel, getLogLevel }
```

### 3.2 x402 Export: `privagent-sdk/x402`

```typescript
// Client-side
export { ZkPaymentHandlerV4, decodePaymentHeaderV4 }
export { privAgentFetchV4, createPrivAgentFetchV4, privAgentFetchV4WithCallback }

// Server-side middleware
export { privAgentPaywallV4 }

// External relay
export { relayViaExternal, getRelayerInfo }

// Server reference implementations
export { createRelayerServer }
export { createFacilitatorServer }
```

### 3.3 ShieldedWallet Class -- Core Methods

```typescript
class ShieldedWallet {
  constructor(config: ShieldedWalletConfig, privateKey?: bigint)

  // Lifecycle
  initialize(): Promise<void>           // Init Poseidon, load persisted notes
  syncTree(): Promise<void>             // Sync Merkle tree from on-chain events

  // Balance
  getBalance(): bigint                  // Sum of unspent, non-pending UTXOs
  getUTXOs(): UTXO[]                   // Available UTXOs

  // Operations
  deposit(amount: bigint): Promise<TransactResult>
  withdraw(amount: bigint, recipient: string, relayer?: string, fee?: bigint): Promise<TransactResult>
  generateTransferProof(amount: bigint, recipientPubkey: bigint, ...): Promise<GenerateTransactProofResult>
  submitTransact(proof: GenerateTransactProofResult): Promise<TransactResult>

  // UTXO Management (for x402 flow)
  lockUTXO(utxo: UTXO): void
  unlockUTXO(utxo: UTXO): void
  consumeUTXO(utxo: UTXO): void
  addUTXO(utxo: UTXO): void
  confirmPayment(inputUTXOs: UTXO[], outputUTXOs: UTXO[]): Promise<void>
  cancelPayment(inputUTXOs: UTXO[]): void

  // Protocol fee
  static calculateProtocolFee(amount, feeBps, minFee, hasTreasury): bigint
  getProtocolFeeParams(): Promise<{ feeBps, minFee, treasury }>

  // Properties
  get publicKey(): bigint
  get circuitDir(): string
  get provider(): Provider
  getTree(): MerkleTree
}
```

**ShieldedWalletConfig**:
```typescript
interface ShieldedWalletConfig {
  provider: Provider;
  signer?: Signer;          // required for deposit/withdraw
  poolAddress: string;
  usdcAddress: string;
  circuitDir: string;       // directory with v4/1x2/ and v4/2x2/ circuit artifacts
  deployBlock?: number;
  noteStore?: NoteStore;    // optional persistent storage (default: MemoryNoteStore)
}
```

---

## 4. Transaction Flows

### 4.1 Deposit (Public USDC -> Shielded UTXO)

1. Create dummy input UTXO (amount=0)
2. Create deposit UTXO with amount = depositAmount - protocolFee
3. Create dummy output UTXO (amount=0, padding for 2-output circuit)
4. Compute extDataHash from ExtData{recipient=0x0, relayer=0x0, fee=0, ...}
5. Generate Groth16 proof via snarkjs (1x2 circuit)
6. Locally verify proof
7. Approve USDC for pool contract (depositAmount + protocolFee)
8. Call `pool.transact()` with publicAmount = depositAmount
9. Contract does `transferFrom(sender, pool, amount - fee)` + `transferFrom(sender, treasury, fee)`
10. Update local Merkle tree and UTXO store

### 4.2 Private Transfer (Shielded -> Shielded)

1. Coin selection: pick UTXOs covering amount + relayerFee + protocolFee
2. Create payment UTXO (amount, recipientPubkey)
3. Create change UTXO (remaining balance, senderPubkey)
4. Encrypt payment note for recipient (ECDH + AES-256-GCM)
5. Encrypt change note for sender (self-encryption)
6. Compute extDataHash
7. Generate Groth16 proof (publicAmount = 0)
8. Submit via relayer or directly call `pool.transact()`
9. On-chain: only nullifiers and commitments visible. No amounts.
10. Recipient scans events, checks view tags, decrypts notes to discover payment

### 4.3 Withdraw (Shielded -> Public USDC)

1. Coin selection covering amount + relayerFee + protocolFee
2. Create dummy payment UTXO (amount=0, because payment is PUBLIC)
3. Create change UTXO for remaining balance
4. Generate proof with publicAmount = -(amount + fee)
5. Submit `pool.transact()`
6. Contract sends USDC to recipient address, relayer fee to relayer, protocol fee to treasury

### 4.4 x402 Payment Flow (Client Perspective)

1. `fetch(url)` -> server returns 402 with `PaymentRequiredV4` body
2. Parse requirements: scheme, price, payToPubkey, serverEcdhPubKey
3. Coin selection + create payment/change UTXOs
4. Encrypt notes for server (ECDH)
5. Generate JoinSplit proof (publicAmount=0, private transfer)
6. Build `V4PaymentPayload`, base64-encode as `Payment` header
7. Retry `fetch(url, { headers: { Payment: ... } })`
8. Server decrypts note, verifies amount >= price
9. Server verifies proof off-chain (snarkjs) to prevent gas griefing
10. Server submits `pool.transact()` on-chain
11. Server returns 200 + `X-Payment-TxHash` header
12. Client verifies TX on-chain, updates local UTXO state

### 4.5 x402 Payment Flow (Server/Middleware Perspective)

The `privAgentPaywallV4` Express middleware:

1. If no `Payment` header -> return 402 with `PaymentRequiredV4`
2. Decode base64 Payment header -> `V4PaymentPayload`
3. Validate structure, circuit config (nIns 1-2, nOuts=2)
4. Recompute and verify extDataHash
5. Validate relayer and fee match config
6. **Decrypt encryptedOutput1** using server's ECDH private key -> verify amount >= price
7. Verify recipient pubkey matches server's Poseidon pubkey
8. Pre-flight checks: root is known, nullifiers not yet used, check nullifier mutex
9. **Off-chain Groth16 proof verification** using verification keys
10. Submit `pool.transact()` on-chain
11. Return 200 with `X-Payment-TxHash` header + call `next()` to serve content

---

## 5. ZK Proof Generation Internals

### 5.1 Circuit Artifacts Required

Per circuit config (e.g., `1x2`), three files are needed:
- `v4/1x2/joinSplit_1x2_js/joinSplit_1x2.wasm` -- WASM witness generator
- `v4/1x2/joinSplit_1x2_final.zkey` -- proving key (from trusted setup)
- `v4/1x2/verification_key.json` -- verification key

### 5.2 Proof Generation Pipeline

```
buildCircuitInput() -> snarkjs.groth16.fullProve(input, wasm, zkey) -> local verify -> format for contract
```

**Circuit input object** (private signals):
```typescript
{
  root: string,
  publicAmount: string,       // field-wrapped for negatives
  extDataHash: string,
  protocolFee: string,
  inputNullifiers: string[],
  outputCommitments: string[],
  inAmount: string[],         // per-input amount
  inPrivateKey: string[],     // per-input private key (0 for dummies)
  inBlinding: string[],       // per-input blinding
  inPathIndices: string[],    // per-input Merkle leaf index
  inPathElements: string[][],  // per-input Merkle path siblings
  outAmount: string[],        // per-output amount
  outPubkey: string[],        // per-output recipient pubkey
  outBlinding: string[],      // per-output blinding
}
```

### 5.3 Dependencies for Proof Generation

- `snarkjs` ^0.7.5 -- Groth16 proof generation and verification
- `circomlibjs` ^0.1.7 -- Poseidon hash function (JS implementation)
- Circuit WASM + zkey files (need to be distributed with the service)

---

## 6. Relayer and Facilitator

### 6.1 Relayer Server (`createRelayerServer`)

Express HTTP server that submits transactions on behalf of clients.

**Endpoints**:
- `GET /v1/health` -- health check
- `GET /v1/info` -- relayer address, fee, gas price, ETH balance
- `POST /v1/relay` -- submit proof on-chain

**POST /v1/relay** body:
```typescript
{
  args: {
    pA: [string, string],
    pB: [[string, string], [string, string]],
    pC: [string, string],
    root: string,
    publicAmount: string,
    extDataHash: string,
    protocolFee: string,
    inputNullifiers: string[],
    outputCommitments: string[],
    viewTags: number[]
  },
  extData: {
    recipient: string,
    relayer: string,
    fee: string,
    encryptedOutput1: string,
    encryptedOutput2: string
  }
}
```

**Response**: `{ success, txHash, blockNumber, gasUsed, fee }`

**Features**: API key auth, rate limiting, off-chain proof verification, gas estimation, 20% gas buffer.

### 6.2 Facilitator Server (`createFacilitatorServer`)

Extends relayer with x402-standard endpoints:

**Endpoints**:
- `GET /health` -- health check
- `GET /info` -- facilitator metadata (schemes, networks, features)
- `POST /verify` -- x402 verification endpoint (submits TX on-chain)
- `/v1/*` -- mounted relayer endpoints

**POST /verify** body:
```typescript
{
  x402Version: number,
  scheme: "zk-exact-v2",
  network: string,
  payload: { args, extData }
}
```

**Response**: `{ valid, txHash, blockNumber, network, settledAt }`

### 6.3 External Relay Client (`relayViaExternal`)

Client-side function to submit proofs to an external relayer:
```typescript
relayViaExternal(request: RelayRequest, relayerUrl: string, apiKey?: string): Promise<RelayResponse>
getRelayerInfo(relayerUrl: string): Promise<RelayerInfo>
```
Includes SSRF protection (blocks private IPs), 60s timeout.

---

## 7. Dependencies Summary

### Runtime Dependencies (SDK)

| Package | Version | Purpose |
|---------|---------|---------|
| `ethers` | ^6.13.0 | Ethereum provider, signer, contract interaction |
| `snarkjs` | ^0.7.5 | Groth16 proof generation and verification |
| `circomlibjs` | ^0.1.7 | Poseidon hash function (JS) |
| `@noble/curves` | ^2.0.1 | secp256k1 ECDH for note encryption |
| `@noble/hashes` | ^2.0.1 | SHA-256, HKDF for key derivation |

### Runtime Dependencies (Relayer/Facilitator)

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^5.0 | HTTP server (dynamic import, not hard dependency) |
| All SDK deps above | | |

### Build/Circuit Dependencies

| Tool | Purpose |
|------|---------|
| `circom` 2.0 | Circuit compiler |
| `snarkjs` | Trusted setup (powers of tau + circuit-specific) |
| Node.js crypto | AES-256-GCM, randomBytes |

### Circuit Artifacts (Must Be Distributed)

These files are required at runtime for proof generation:
```
circuits/build/v4/1x2/
  joinSplit_1x2_js/joinSplit_1x2.wasm    (~large, WASM)
  joinSplit_1x2_final.zkey               (~large, proving key)
  verification_key.json                  (~small, for off-chain verify)

circuits/build/v4/2x2/
  joinSplit_2x2_js/joinSplit_2x2.wasm
  joinSplit_2x2_final.zkey
  verification_key.json
```

---

## 8. What to Expose as HTTP API Endpoints

Based on the analysis, here are the operations that would need HTTP API endpoints for a privacy proof service:

### 8.1 Wallet Management

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /wallet/create` | POST | Create new ShieldedWallet (returns publicKey) | `new ShieldedWallet()` + `initialize()` |
| `POST /wallet/import` | POST | Import wallet from private key | `new ShieldedWallet(config, privateKey)` |
| `GET /wallet/balance` | GET | Get shielded balance | `wallet.getBalance()` |
| `GET /wallet/utxos` | GET | List available UTXOs | `wallet.getUTXOs()` |
| `POST /wallet/sync` | POST | Sync Merkle tree from chain | `wallet.syncTree()` |

### 8.2 Core Operations

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /deposit` | POST | Deposit USDC into shielded pool | `wallet.deposit(amount)` |
| `POST /transfer/proof` | POST | Generate private transfer proof (no submission) | `wallet.generateTransferProof(amount, recipientPubkey)` |
| `POST /transfer/submit` | POST | Submit generated proof on-chain | `wallet.submitTransact(proof)` |
| `POST /withdraw` | POST | Withdraw shielded USDC to address | `wallet.withdraw(amount, recipient)` |

### 8.3 x402 Payment (Client-Side)

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /x402/pay` | POST | Handle 402 response, generate payment proof | `ZkPaymentHandlerV4.createPayment()` |
| `POST /x402/confirm` | POST | Confirm payment after TX hash verification | `wallet.confirmPayment()` |
| `POST /x402/cancel` | POST | Cancel pending payment (unlock UTXOs) | `wallet.cancelPayment()` |

### 8.4 x402 Verification (Server-Side / Facilitator)

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /verify` | POST | Verify proof + submit on-chain (facilitator) | `pool.transact()` |
| `GET /info` | GET | Facilitator info (schemes, networks, fees) | -- |
| `GET /health` | GET | Health check | -- |

### 8.5 Relay

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /v1/relay` | POST | Submit proof via relayer | `pool.transact()` |
| `GET /v1/info` | GET | Relayer info (address, fee, gas price) | -- |

### 8.6 Utility

| Endpoint | Method | Purpose | SDK Method |
|----------|--------|---------|------------|
| `POST /poseidon/init` | POST | Initialize Poseidon (required once) | `initPoseidon()` |
| `GET /pool/info` | GET | Pool tree info, balance, fee params | `pool.getTreeInfo()`, etc. |
| `POST /note/encrypt` | POST | Encrypt a note for a recipient | `encryptNote()` |
| `POST /note/decrypt` | POST | Decrypt a note | `decryptNote()` |
| `POST /keypair/derive` | POST | Derive Poseidon public key from private | `derivePublicKey()` |

---

## 9. Critical Implementation Notes

### 9.1 State Management

The ShieldedWallet is **stateful** -- it tracks UTXOs, the Merkle tree, and pending locks in memory. An HTTP service wrapping this must:
- Maintain wallet instances per user/session
- Handle concurrent access (UTXO locking via `pending` flag)
- Persist notes via `NoteStore` (FileNoteStore available, or implement custom)
- Periodically sync tree from chain events (`syncTree()`)

### 9.2 Proof Generation Performance

- snarkjs Groth16 proof generation is **CPU-intensive** (seconds to tens of seconds)
- Circuit WASM and zkey files are **large** (must be local to the server)
- The SDK has a 30-second timeout on proof generation for x402 flows
- Consider: worker threads, proof generation queue, pre-computation

### 9.3 Security Considerations

- Private keys (Poseidon private key for UTXO ownership, ECDH private key for note encryption, Ethereum private key for signing) must be stored securely server-side
- Nullifier mutex is critical to prevent race conditions (already implemented in middleware)
- Off-chain proof verification before on-chain submission prevents gas griefing
- Rate limiting per IP is implemented
- API key authentication available for relayer/facilitator

### 9.4 Field Arithmetic

All values are in the BN254 scalar field:
```
FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```
Negative publicAmounts are field-wrapped: `FIELD_SIZE + publicAmount`

### 9.5 Poseidon Initialization

`initPoseidon()` must be called once before any cryptographic operations. It loads the Poseidon WASM module from circomlibjs. This is async and takes ~100ms.

### 9.6 Environment Variables Required

```env
BASE_SEPOLIA_RPC=https://sepolia.base.org
PRIVATE_KEY=0x...                     # Ethereum signer for on-chain TX
SHIELDED_POOL_V4=0x8F1ae8209156C22dFD972352A415880040fB0b0c
USDC_ADDRESS=0x036CbD53842c5426634e7929541eC2318f3dCF7e
DEPLOY_BLOCK=38347380
POSEIDON_HASHER=0x70Aa742C113218a12A6582f60155c2B299551A43
VERIFIER_1X2=0xC53c8E05661450919951f51E4da829a3AABD76A2
VERIFIER_2X2=0xE77ad940291c97Ae4dC43a6b9Ffb43a3AdCd4769
```

---

## 10. Monorepo Structure

```
privagent/
  package.json            # pnpm workspace root
  pnpm-workspace.yaml     # packages: [sdk, relayer, app, packages/*, circuits]
  contracts/              # Foundry project (106 tests)
    src/
      ShieldedPoolV4.sol  # Main pool contract - single transact() entry point
      PoseidonHasher.sol  # On-chain Poseidon wrapper
      PoseidonT3.sol      # Poseidon T3 round constants (~28KB)
      StealthRegistry.sol # V3 legacy stealth address registry
      verifiers/          # snarkjs-generated Groth16 verifiers
    test/
    script/Deploy.s.sol
  circuits/
    joinSplit.circom      # Main JoinSplit circuit (nIns x nOuts)
    merkleProof.circom    # Merkle inclusion proof sub-circuit
    scripts/build-v4.sh   # Build script for circuit compilation
    generated/            # Verifier Solidity from snarkjs
  sdk/                    # TypeScript SDK (109 tests, published as privagent-sdk)
    src/
      index.ts            # Main entry
      types.ts            # All type definitions
      poseidon.ts         # Poseidon hash wrapper (circomlibjs)
      merkle.ts           # In-memory Merkle tree
      v4/                 # UTXO engine
        shieldedWallet.ts # ShieldedWallet class (main API)
        utxo.ts           # UTXO create/serialize/nullifier
        keypair.ts        # Poseidon keypair
        coinSelection.ts  # UTXO selection algorithm
        joinSplitProver.ts # Groth16 proof generation
        extData.ts        # ExtData hash computation
        noteEncryption.ts # ECDH + AES-256-GCM
        noteStore.ts      # Memory/File persistence
        treeSync.ts       # Sync tree from chain events
        viewTag.ts        # View tag generation/checking
        signalIndex.ts    # Public signal index constants
      x402/               # x402 protocol integration
        middlewareV2.ts    # Express paywall middleware (server-side)
        zkExactSchemeV2.ts # Payment handler (client-side)
        zkFetchV2.ts      # x402-aware fetch wrapper
        externalRelay.ts  # External relayer client
        relayerServer.ts  # Relayer Express server
        facilitatorServer.ts # Facilitator Express server
      erc8004/            # ERC-8004 agent identity helpers
      utils/logger.ts     # Structured logging
  relayer/                # Standalone relayer (V3 legacy, deprecated)
  app/                    # Next.js frontend (Tailwind)
  packages/
    virtuals-plugin/      # Virtuals GAME framework plugin (29 tests)
    openclaw-skill/       # OpenClaw agent skill (38 tests)
  examples/
    basic-transfer/       # Deposit -> Transfer -> Withdraw demo
    express-server/       # Express middleware paywall example
    eliza-plugin/         # ElizaOS integration
    erc8004-integration/  # ERC-8004 agent registration + payment proof
    virtuals-integration/ # Virtuals GAME integration
  demo/                   # On-chain demo scripts
  docs/                   # Protocol docs, lightpaper, roadmap
```

---

## 11. Integration Strategy for HTTP API Service

### Minimal Viable Service

To expose PrivAgent as an HTTP API, the minimum components needed are:

1. **ShieldedWallet management** -- create, persist, and lookup wallets by identifier
2. **Poseidon initialization** -- one-time async init on server start
3. **Circuit artifacts** -- distribute wasm/zkey files alongside the service
4. **Ethereum provider** -- JSON-RPC connection to Base Sepolia
5. **Signer management** -- securely hold Ethereum private keys for on-chain TX

### Dependencies to Install

```bash
npm install privagent-sdk ethers express @noble/curves @noble/hashes snarkjs circomlibjs
```

Or, since the SDK bundles most dependencies:
```bash
npm install privagent-sdk express
```

### Key Integration Points

1. **Proof generation is the bottleneck** -- consider async job queue with status polling
2. **Tree sync can be slow** -- cache tree state, incremental updates
3. **UTXO state is per-wallet** -- need session/wallet management layer
4. **Circuit artifacts are large** -- must be on local filesystem (not fetched remotely)
5. **Two key types per user**: Poseidon private key (UTXO ownership) + ECDH private key (note encryption)

### Approximate Request/Response Sizes

| Operation | Request | Response | Time |
|-----------|---------|----------|------|
| Deposit | ~200B | ~500B + TX receipt | 5-30s (proof + TX) |
| Transfer proof | ~200B | ~5KB (proof + encrypted notes) | 3-20s (proof only) |
| Submit transact | ~5KB | ~500B + TX receipt | 3-10s (TX only) |
| x402 payment | ~200B | ~5KB (Payment header) | 3-20s (proof) |
| Balance | ~50B | ~100B | instant |
| Sync tree | ~50B | ~100B | 1-30s (event scan) |
