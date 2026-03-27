import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

// --- Configuration ---
const PORT = Number(process.env.PORT) || 3403;
const PRIVATE_KEY = (process.env.SERVER_PRIVATE_KEY ||
  generatePrivateKey()) as `0x${string}`;
const account = privateKeyToAccount(PRIVATE_KEY);
const PATHUSD = "0x20c000000000000000000000b9537d11c60e8b50" as const;
const OWNER_WALLET = "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7" as const;

// Base Sepolia PrivAgent contracts
const POOL_ADDRESS = "0x8F1ae8209156C22dFD972352A415880040fB0b0c";
const USDC_BASE = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const BASE_RPC = "https://sepolia.base.org";
const DEPLOY_BLOCK = 38347380;

console.log(`Server wallet: ${account.address}`);
console.log(`Payment recipient: ${OWNER_WALLET}`);

// --- Lazy-loaded privacy engine ---
let privacyEngine: PrivacyEngine | null = null;

interface PrivacyEngine {
  initialized: boolean;
  generateDepositProof(amount: bigint): Promise<any>;
  generateTransferProof(amount: bigint, recipientPubkey: string): Promise<any>;
  generateWithdrawProof(amount: bigint, recipient: string): Promise<any>;
  verifyProof(proof: any, publicSignals: string[]): Promise<boolean>;
  getPoolInfo(): any;
}

async function getEngine(): Promise<PrivacyEngine> {
  if (privacyEngine?.initialized) return privacyEngine;

  // Initialize the privacy engine with circuit artifacts
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const circuitDir = resolve(__dirname, "../circuits");

  // For now, we use snarkjs directly (same pattern as ZKProver)
  const snarkjs = await import("snarkjs");

  const circuits: Record<string, { wasm: string; zkey: string; vkey: any }> = {};

  for (const id of ["1x2", "2x2"]) {
    const dir = resolve(circuitDir, id);
    try {
      circuits[id] = {
        wasm: resolve(dir, `joinSplit_${id}.wasm`),
        zkey: resolve(dir, `joinSplit_${id}_final.zkey`),
        vkey: JSON.parse(readFileSync(resolve(dir, "verification_key.json"), "utf-8")),
      };
    } catch {
      console.warn(`Circuit ${id} artifacts not found, skipping`);
    }
  }

  // Pre-compute empty Merkle tree root (depth 20) and cache Poseidon
  const { initPoseidon } = await import("./crypto.js");
  const poseidon = await initPoseidon();

  // Compute empty Merkle root: hash(0,0) repeated 20 times
  let currentHash = BigInt(0);
  for (let i = 0; i < 20; i++) {
    currentHash = poseidon.hash2(currentHash, currentHash);
  }
  const emptyRoot = currentHash;

  privacyEngine = {
    initialized: true,

    async generateDepositProof(amount: bigint) {
      // Deposit: publicAmount > 0, 1 dummy input, 1 real output + 1 dummy output
      // Uses 1x2 circuit (same approach as ZKProver test-prove.ts)
      const circuit = circuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      // Dummy input UTXO (amount=0, sits at leaf 0 of empty tree)
      const dummyKey = BigInt(1);
      const dummyPubkey = poseidon.hash1(dummyKey);
      const dummyCommitment = poseidon.hash3(BigInt(0), dummyPubkey, BigInt(0));
      const dummyNullifier = poseidon.hash3(dummyCommitment, BigInt(0), dummyKey);

      // Output 1: real deposit UTXO
      const recipientKey = BigInt(55555);
      const recipientPubkey = poseidon.hash1(recipientKey);
      const blinding = BigInt(Math.floor(Math.random() * 2 ** 48));
      const commitment = poseidon.hash3(amount, recipientPubkey, blinding);

      // Output 2: zero-change dummy
      const dummyOutCommitment = poseidon.hash3(BigInt(0), dummyPubkey, BigInt(0));

      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      const input = {
        root: emptyRoot.toString(),
        publicAmount: amount.toString(),
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [dummyNullifier.toString()],
        outputCommitments: [commitment.toString(), dummyOutCommitment.toString()],
        inAmount: ["0"],
        inPrivateKey: [dummyKey.toString()],
        inBlinding: ["0"],
        inPathIndices: ["0"],
        inPathElements: [Array(20).fill("0")],
        outAmount: [amount.toString(), "0"],
        outPubkey: [recipientPubkey.toString(), dummyPubkey.toString()],
        outBlinding: [blinding.toString(), "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        circuit.wasm,
        circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;

      // Verify locally
      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true,
        operation: "deposit",
        amount: amount.toString(),
        proof,
        publicSignals,
        commitment: commitment.toString(),
        valid,
        generationTimeMs,
      };
    },

    async generateTransferProof(amount: bigint, recipientPubkey: string) {
      // Transfer: publicAmount = 0, private UTXO -> private UTXO
      const circuit = circuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      // Sender input UTXO (amount matches output for balance)
      const senderKey = BigInt(1);
      const senderPubkey = poseidon.hash1(senderKey);
      const inBlinding = BigInt(0);
      const inCommitment = poseidon.hash3(amount, senderPubkey, inBlinding);
      const nullifier = poseidon.hash3(inCommitment, BigInt(0), senderKey);

      const recipPubkey = BigInt(recipientPubkey);

      // Output 1: payment to recipient
      const payBlinding = BigInt(Math.floor(Math.random() * 2 ** 48));
      const payCommitment = poseidon.hash3(amount, recipPubkey, payBlinding);

      // Output 2: zero-change
      const changeCommitment = poseidon.hash3(BigInt(0), senderPubkey, BigInt(0));

      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      // For transfer the input UTXO must exist in the tree. We use empty tree
      // with the input commitment at index 0 — but the empty tree has zeros.
      // For a valid demo, we use a dummy input with amount=transfer amount
      // and set the tree root to match. In this demo, we build a custom root
      // by replacing leaf 0 with inCommitment.
      let customRoot = inCommitment;
      let sibling = BigInt(0);
      for (let i = 0; i < 20; i++) {
        const left = customRoot;
        // path index bit 0 => left child, sibling on right
        sibling = i === 0 ? BigInt(0) : poseidon.hash2(sibling, sibling);
        customRoot = poseidon.hash2(left, sibling);
      }

      // Recompute siblings for the path
      const pathElements: string[] = [];
      let sib = BigInt(0);
      for (let i = 0; i < 20; i++) {
        pathElements.push(sib.toString());
        sib = poseidon.hash2(sib, sib);
      }

      const input = {
        root: customRoot.toString(),
        publicAmount: "0",
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [nullifier.toString()],
        outputCommitments: [payCommitment.toString(), changeCommitment.toString()],
        inAmount: [amount.toString()],
        inPrivateKey: [senderKey.toString()],
        inBlinding: [inBlinding.toString()],
        inPathIndices: ["0"],
        inPathElements: [pathElements],
        outAmount: [amount.toString(), "0"],
        outPubkey: [recipPubkey.toString(), senderPubkey.toString()],
        outBlinding: [payBlinding.toString(), "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        circuit.wasm,
        circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;

      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true,
        operation: "transfer",
        amount: amount.toString(),
        recipientPubkey: recipientPubkey,
        proof,
        publicSignals,
        paymentCommitment: payCommitment.toString(),
        changeCommitment: changeCommitment.toString(),
        valid,
        generationTimeMs,
      };
    },

    async generateWithdrawProof(amount: bigint, recipient: string) {
      // Withdraw: publicAmount < 0 (negative = outflow from pool, field-wrapped)
      const circuit = circuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      const fieldPrime = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

      // Input UTXO to spend
      const privKey = BigInt(1);
      const pubkey = poseidon.hash1(privKey);
      const inBlinding = BigInt(0);
      const inCommitment = poseidon.hash3(amount, pubkey, inBlinding);
      const nullifier = poseidon.hash3(inCommitment, BigInt(0), privKey);

      // Build custom Merkle root with inCommitment at leaf 0
      let customRoot = inCommitment;
      let sib = BigInt(0);
      const pathElements: string[] = [];
      for (let i = 0; i < 20; i++) {
        pathElements.push(sib.toString());
        customRoot = poseidon.hash2(customRoot, sib);
        sib = poseidon.hash2(sib, sib);
      }

      // Dummy outputs (both zero)
      const dummyCommitment1 = poseidon.hash3(BigInt(0), pubkey, BigInt(0));
      const dummyCommitment2 = poseidon.hash3(BigInt(0), pubkey, BigInt(0));

      // publicAmount is negative for withdrawals (field-wrapped)
      const publicAmount = (fieldPrime - amount) % fieldPrime;

      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      const input = {
        root: customRoot.toString(),
        publicAmount: publicAmount.toString(),
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [nullifier.toString()],
        outputCommitments: [dummyCommitment1.toString(), dummyCommitment2.toString()],
        inAmount: [amount.toString()],
        inPrivateKey: [privKey.toString()],
        inBlinding: [inBlinding.toString()],
        inPathIndices: ["0"],
        inPathElements: [pathElements],
        outAmount: ["0", "0"],
        outPubkey: [pubkey.toString(), pubkey.toString()],
        outBlinding: ["0", "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        circuit.wasm,
        circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;

      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true,
        operation: "withdraw",
        amount: amount.toString(),
        recipient,
        proof,
        publicSignals,
        valid,
        generationTimeMs,
      };
    },

    async verifyProof(proof: any, publicSignals: string[]) {
      const circuit = circuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");
      return snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);
    },

    getPoolInfo() {
      return {
        pool: POOL_ADDRESS,
        chain: "base-sepolia",
        chainId: 84532,
        usdc: USDC_BASE,
        deployBlock: DEPLOY_BLOCK,
        circuits: Object.keys(circuits),
        merkleDepth: 20,
        maxLeaves: 1048576,
      };
    },
  };

  return privacyEngine;
}

// --- App ---
async function main() {
  const app = new Hono();
  app.use("*", cors());

  // Landing page
  app.get("/", (c) => {
    c.header("Content-Type", "text/html");
    return c.body(`<!DOCTYPE html>
<html><head><title>PrivAgent Service</title>
<style>body{font-family:system-ui;max-width:700px;margin:60px auto;padding:0 20px;background:#0a0a0a;color:#e0e0e0}
h1{color:#fff}a{color:#58a6ff}code{background:#1a1a2e;padding:2px 6px;border-radius:4px;font-size:14px}
pre{background:#1a1a2e;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px}
.badge{display:inline-block;background:#238636;color:#fff;padding:4px 10px;border-radius:12px;font-size:13px;margin:4px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:8px;text-align:left}th{background:#1a1a2e}</style></head>
<body>
<h1>PrivAgent Service</h1>
<p><span class="badge">LIVE</span> <span class="badge">Privacy</span> <span class="badge">MPP</span></p>
<p>Privacy-preserving payment proofs via <a href="https://mpp.dev">Tempo MPP</a>. Shielded deposits, transfers, and withdrawals.</p>

<h2>Endpoints</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>GET</td><td><a href="/health">/health</a></td><td>Free</td><td>Health check</td></tr>
<tr><td>GET</td><td><a href="/pool">/pool</a></td><td>Free</td><td>Pool info & circuits</td></tr>
<tr><td>POST</td><td>/privacy/deposit</td><td>$0.03</td><td>Generate deposit proof</td></tr>
<tr><td>POST</td><td>/privacy/transfer</td><td>$0.03</td><td>Generate private transfer proof</td></tr>
<tr><td>POST</td><td>/privacy/withdraw</td><td>$0.03</td><td>Generate withdrawal proof</td></tr>
<tr><td>POST</td><td>/verify</td><td>Free</td><td>Verify a proof</td></tr>
</table>

<h2>Links</h2>
<p><a href="https://github.com/Himess/privagent">PrivAgent</a> · <a href="/llms.txt">llms.txt</a> · <a href="/pool">Pool Info</a></p>
</body></html>`);
  });

  // Health check
  app.get("/health", (c) =>
    c.json({
      status: "ok",
      wallet: OWNER_WALLET,
      chain: "tempo-moderato",
      chainId: 42431,
      privacyPool: POOL_ADDRESS,
      poolChain: "base-sepolia",
    })
  );

  // Pool info
  app.get("/pool", async (c) => {
    const engine = await getEngine();
    return c.json(engine.getPoolInfo());
  });

  // LLMs.txt
  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain");
    return c.body(`# PrivAgent Service
> Privacy-preserving payment proofs via MPP. Shielded deposits, transfers, and withdrawals.

## Endpoints
- GET /health — Health check (free)
- GET /pool — Pool info and available circuits (free)
- POST /privacy/deposit — Generate shielded deposit proof ($0.03 MPP)
- POST /privacy/transfer — Generate private transfer proof ($0.03 MPP)
- POST /privacy/withdraw — Generate withdrawal proof ($0.03 MPP)
- POST /verify — Verify a proof (free)

## Pricing
- All privacy proofs: $0.03 per proof
- Payment: USDC via Tempo MPP (automatic 402 flow)

## What This Does
Generates Groth16 ZK proofs for privacy-preserving UTXO transactions on Base.
Supports shielded deposits (public → private), private transfers, and withdrawals (private → public).
Built on the PrivAgent ZK-UTXO architecture with Poseidon hashing, BN254 curve.

## Source
https://github.com/Himess/privagent`);
  });

  // OpenAPI Discovery
  app.get("/openapi.json", (c) =>
    c.json({
      openapi: "3.1.0",
      info: {
        title: "PrivAgent Service",
        version: "1.0.0",
        description: "Privacy-preserving payment proofs on Tempo MPP. Shielded deposits, transfers, and withdrawals.",
        "x-guidance": "Use PrivAgent Service to generate ZK proofs for privacy-preserving UTXO transactions. POST to /privacy/deposit to shield funds, /privacy/transfer for private transfers, /privacy/withdraw to unshield. Payment is automatic via MPP 402 flow. Verification at /verify is free.",
      },
      "x-service-info": {
        categories: ["compute", "developer-tools"],
        docs: {
          homepage: "https://github.com/Himess/privagent",
          llms: "https://himess-privagent-service.hf.space/llms.txt",
        },
      },
      servers: [{ url: "https://himess-privagent-service.hf.space" }],
      paths: {
        "/health": {
          get: {
            summary: "Health check",
            description: "Returns service status and pool info. Free.",
            security: [],
            responses: {
              "200": {
                description: "Service is healthy",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        status: { type: "string" },
                        wallet: { type: "string" },
                        privacyPool: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/privacy/deposit": {
          post: {
            operationId: "deposit",
            summary: "Generate shielded deposit proof",
            tags: ["Privacy"],
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units (6 decimals). e.g. '10000000' = 10 USDC" },
                    },
                    required: ["amount"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Deposit proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        commitment: { type: "string" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/privacy/transfer": {
          post: {
            operationId: "transfer",
            summary: "Generate private transfer proof",
            tags: ["Privacy"],
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
                      recipientPubkey: { type: "string", minLength: 1, description: "Recipient Poseidon public key" },
                    },
                    required: ["amount", "recipientPubkey"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Transfer proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        paymentCommitment: { type: "string" },
                        changeCommitment: { type: "string" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/privacy/withdraw": {
          post: {
            operationId: "withdraw",
            summary: "Generate withdrawal proof",
            tags: ["Privacy"],
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
                      recipient: { type: "string", minLength: 1, description: "Recipient Ethereum address for withdrawal" },
                    },
                    required: ["amount", "recipient"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Withdrawal proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/verify": {
          post: {
            summary: "Verify a proof",
            description: "Verify a previously generated privacy proof. Free.",
            security: [],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      proof: { type: "object", description: "Groth16 proof object" },
                      publicSignals: { type: "array", items: { type: "string" } },
                    },
                    required: ["proof", "publicSignals"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Verification result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        valid: { type: "boolean" },
                        verificationTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    })
  );

  // .well-known/x402
  app.get("/.well-known/x402", (c) =>
    c.json({
      version: 1,
      resources: [
        "POST /privacy/deposit",
        "POST /privacy/transfer",
        "POST /privacy/withdraw",
      ],
      description: "PrivAgent Service: privacy-preserving payment proofs via MPP. Shielded deposits ($0.03), transfers ($0.03), and withdrawals ($0.03).",
    })
  );

  // --- Privacy proof endpoints ---
  async function handleDeposit(c: any) {
    let body: { amount: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    if (!body.amount) return c.json({ error: "amount is required" }, 400);

    try {
      const engine = await getEngine();
      const result = await engine.generateDepositProof(BigInt(body.amount));
      return c.json(result);
    } catch (e) {
      return c.json({ error: "Deposit proof generation failed", details: (e as Error).message }, 500);
    }
  }

  async function handleTransfer(c: any) {
    let body: { amount: string; recipientPubkey: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    if (!body.amount || !body.recipientPubkey) {
      return c.json({ error: "amount and recipientPubkey are required" }, 400);
    }

    try {
      const engine = await getEngine();
      const result = await engine.generateTransferProof(BigInt(body.amount), body.recipientPubkey);
      return c.json(result);
    } catch (e) {
      return c.json({ error: "Transfer proof generation failed", details: (e as Error).message }, 500);
    }
  }

  async function handleWithdraw(c: any) {
    let body: { amount: string; recipient: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    if (!body.amount || !body.recipient) {
      return c.json({ error: "amount and recipient are required" }, 400);
    }

    try {
      const engine = await getEngine();
      const result = await engine.generateWithdrawProof(BigInt(body.amount), body.recipient);
      return c.json(result);
    } catch (e) {
      return c.json({ error: "Withdrawal proof generation failed", details: (e as Error).message }, 500);
    }
  }

  // Verify proof (free)
  app.post("/verify", async (c) => {
    let body: { proof: any; publicSignals: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }
    if (!body.proof || !body.publicSignals) {
      return c.json({ error: "proof and publicSignals are required" }, 400);
    }

    try {
      const engine = await getEngine();
      const startTime = Date.now();
      const valid = await engine.verifyProof(body.proof, body.publicSignals);
      return c.json({ valid, verificationTimeMs: Date.now() - startTime });
    } catch (e) {
      return c.json({ error: "Verification failed", details: (e as Error).message }, 500);
    }
  });

  // Setup MPP-gated routes
  try {
    if (process.env.NO_MPP === "1") throw new Error("MPP disabled");
    const { Mppx, tempo } = await import("mppx/hono");
    const mppx = Mppx.create({
      realm: "himess-privagent-service.hf.space",
      methods: [
        tempo({
          currency: PATHUSD,
          recipient: OWNER_WALLET,
          feePayer: true,
        }),
      ],
      secretKey: process.env.MPP_SECRET_KEY || "dev-secret-key-change-in-production",
    });

    app.post("/privacy/deposit", mppx.charge({ amount: "0.03", description: "Shielded deposit proof" }), handleDeposit);
    app.post("/privacy/transfer", mppx.charge({ amount: "0.03", description: "Private transfer proof" }), handleTransfer);
    app.post("/privacy/withdraw", mppx.charge({ amount: "0.03", description: "Withdrawal proof" }), handleWithdraw);
    console.log("MPP payment gating enabled");
  } catch (e) {
    console.warn("mppx not available, running free:", (e as Error).message);
    app.post("/privacy/deposit", handleDeposit);
    app.post("/privacy/transfer", handleTransfer);
    app.post("/privacy/withdraw", handleWithdraw);
  }

  // Start
  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`\nPrivAgent Service running on http://localhost:${PORT}`);
    console.log(`\nEndpoints:`);
    console.log(`  GET  /health             — Health check (free)`);
    console.log(`  GET  /pool               — Pool info (free)`);
    console.log(`  POST /privacy/deposit    — Shielded deposit proof ($0.03 MPP)`);
    console.log(`  POST /privacy/transfer   — Private transfer proof ($0.03 MPP)`);
    console.log(`  POST /privacy/withdraw   — Withdrawal proof ($0.03 MPP)`);
    console.log(`  POST /verify             — Verify proof (free)`);
  });
}

main().catch(console.error);
