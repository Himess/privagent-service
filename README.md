---
title: PrivAgent Service
emoji: "\U0001F512"
colorFrom: green
colorTo: indigo
sdk: docker
app_port: 7860
---

# PrivAgent Service

Privacy-preserving payment proofs via [Tempo MPP](https://mpp.dev). Shielded deposits, transfers, and withdrawals using Groth16 ZK proofs over JoinSplit UTXO circuits.

## Endpoints

| Method | Path | Cost | Description |
|--------|------|------|-------------|
| GET | `/health` | Free | Health check |
| GET | `/pool` | Free | Pool info & available circuits |
| GET | `/openapi.json` | Free | OpenAPI 3.1 spec |
| GET | `/llms.txt` | Free | Agent discovery |
| POST | `/privacy/deposit` | $0.03 | Generate shielded deposit proof |
| POST | `/privacy/transfer` | $0.03 | Generate private transfer proof |
| POST | `/privacy/withdraw` | $0.03 | Generate withdrawal proof |
| POST | `/verify` | Free | Verify a proof |

## How It Works

PrivAgent generates Groth16 zero-knowledge proofs for a UTXO-based privacy system:

- **Deposit**: Shield funds from public to private (publicAmount > 0)
- **Transfer**: Move funds privately between UTXO commitments (publicAmount = 0)
- **Withdraw**: Unshield funds from private to public (publicAmount < 0, field-wrapped)

Each proof uses the JoinSplit circuit (1 input, 2 outputs, Merkle depth 20) with Poseidon hashing over the BN254 curve.

## Usage

### Deposit (shield funds)
```bash
curl -X POST https://himess-privagent-service.hf.space/privacy/deposit \
  -H "Content-Type: application/json" \
  -d '{"amount": "1000000"}'
```

### Transfer (private payment)
```bash
curl -X POST https://himess-privagent-service.hf.space/privacy/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount": "1000000", "recipientPubkey": "12345"}'
```

### Withdraw (unshield funds)
```bash
curl -X POST https://himess-privagent-service.hf.space/privacy/withdraw \
  -H "Content-Type: application/json" \
  -d '{"amount": "1000000", "recipient": "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7"}'
```

### Verify a proof
```bash
curl -X POST https://himess-privagent-service.hf.space/verify \
  -H "Content-Type: application/json" \
  -d '{"proof": {...}, "publicSignals": [...]}'
```

## Payment

Paid endpoints require USDC payment via Tempo MPP (automatic 402 flow). Use `tempo request` or any MPP-compatible client.

## Local Development

```bash
npm install
NO_MPP=1 npx tsx src/server.ts
```

## Architecture

- **Runtime**: Node.js + Hono
- **Proof system**: Groth16 via snarkjs
- **Hash function**: Poseidon (BN254) via circomlibjs
- **Payment**: Tempo MPP via mppx
- **Circuits**: JoinSplit 1x2 and 2x2 (shared with [ZKProver](https://github.com/Himess/zk-proof-service))

## License

MIT
