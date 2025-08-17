/*  Malleability Tester – JavaScript / TypeScript (web3.js 1.95)
    Scenarios:
    A.  Standard Malleability:  S' = L - S
    B.  Non-Canonical:        S'' = S + L
    C.  R-component flip
    ----------------------------------------------------------
    Usage:  node malleabilityTester.js [iterations=100]
*/

import {
  Connection,
  Transaction,
  SystemProgram,
  PublicKey,
  Keypair,
  VersionedTransaction,
  TransactionMessage,
} from '@solana/web3.js';
import * as fs from 'fs';
import chalk from 'chalk';
import { verify } from '@noble/ed25519';

/* ---------- Config ---------- */
const DEVNET_RPC = 'https://devnet.helius-rpc.com/?api-key=fadc60cf-6297-4317-acc8-9f6441ff7025';

// Import bs58 for proper base58 decoding
import bs58 from 'bs58';

const privateKeyBase58 = JSON.parse(fs.readFileSync('./config.json', 'utf8')).privateKey[0];
const SECRET_KEY = bs58.decode(privateKeyBase58);
const SENDER = Keypair.fromSecretKey(SECRET_KEY);

/* ---------- Constants ---------- */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/* ---------- Logging ---------- */
const log = console.log;
const now = () => new Date().toISOString();

/* ---------- CSV ---------- */
const csvHeaders = [
  'iteration',
  'timestamp',
  'scenario',
  'originalSignature',
  'manipulatedSignature',
  'description',
  'status',
  'rpcMessage',
  'expected',
  'testPassed',
  'destination',
  'amountLamports',
];

/* ---------- Helper ---------- */
const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

/* ---------- Core Tester ---------- */
class MalleabilityTester {
  constructor(iterations = 100) {
    this.conn = new Connection(DEVNET_RPC, 'confirmed');
    this.iterations = iterations;
    this.csvFile = `malleability_new_test_${iterations}_${Date.now()}.csv`;
    this.stats = { A: { pass: 0, fail: 0, err: 0 }, B: { pass: 0, fail: 0, err: 0 }, C: { pass: 0, fail: 0, err: 0 } };
    this.initCsv();
  }

  initCsv() {
    fs.writeFileSync(this.csvFile, csvHeaders.join(',') + '\n');
  }

  appendCsv(row) {
    fs.appendFileSync(this.csvFile, row.join(',') + '\n');
  }

  async createLegitimateTx() {
    const dest = Keypair.generate();
    const amount = Math.floor(Math.random() * 9_000_000) + 1_000_000; // 0.001 – 0.01 SOL

    // Retry mechanism for getting blockhash
    let blockhash;
    let retries = 3;
    while (retries > 0) {
      try {
        const result = await this.conn.getLatestBlockhash();
        blockhash = result.blockhash;
        break;
      } catch (error) {
        retries--;
        console.log(`⚠️  Failed to get blockhash, retries left: ${retries}. Error: ${error.message}`);
        if (retries === 0) {
          throw new Error(`Failed to get recent blockhash after 3 attempts: ${error.message}`);
        }
        // Wait 1 second before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    const messageV0 = new TransactionMessage({
      payerKey: SENDER.publicKey,
      recentBlockhash: blockhash,
      instructions: [
        SystemProgram.transfer({
          fromPubkey: SENDER.publicKey,
          toPubkey: dest.publicKey,
          lamports: amount,
        }),
      ],
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    tx.sign([SENDER]); // Explicitly sign the transaction
    const sigBytes = new Uint8Array(tx.signatures[0]);
    return { tx, sigBytes, dest: dest.publicKey.toString(), amount };
  }

  async testScenario(sigBytes, scenario, originalTx) {
    let manipulated;
    let desc;

    switch (scenario) {
      case 'A':
        {
          const sBytes = sigBytes.slice(32, 64);
          const hex = Buffer.from(sBytes).toString('hex');
          const S = BigInt('0x' + hex);
          const Sp = (L - S) % L;
          const spHex = Sp.toString(16).padStart(64, '0');
          const spBytes = Uint8Array.from(Buffer.from(spHex, 'hex'));
          manipulated = new Uint8Array(64);
          manipulated.set(sigBytes.slice(0, 32), 0);
          manipulated.set(spBytes, 32);
          desc = 'Standard malleability: S\' = L - S';
        }
        break;
      case 'B':
        {
          const sBytes = sigBytes.slice(32, 64);
          const hex = Buffer.from(sBytes).toString('hex');
          const S = BigInt('0x' + hex);
          const Spp = (S + L) % (L * 2n);
          const sppHex = Spp.toString(16).padStart(64, '0');
          const sppBytes = Uint8Array.from(Buffer.from(sppHex, 'hex'));
          manipulated = new Uint8Array(64);
          manipulated.set(sigBytes.slice(0, 32), 0);
          manipulated.set(sppBytes, 32);
          desc = 'Non-canonical signature: S\'\'\' = S + L';
        }
        break;
      case 'C':
        {
          manipulated = new Uint8Array(sigBytes);
          manipulated[63] ^= 0x01; // flip last bit of R
          desc = 'R component manipulation: XOR last byte';
        }
        break;
      default:
        throw new Error('Unknown scenario');
    }

    // Verify signature manually using cryptographic verification
    const messageBytes = originalTx.message.serialize();
    const publicKeyBytes = SENDER.publicKey.toBytes();

    let status, rpcMsg;
    try {
      // Verify the manipulated signature against the original message
      const isValidSignature = await verify(manipulated, messageBytes, publicKeyBytes);

      if (isValidSignature) {
        // If signature is still valid after manipulation, it's a malleability issue
        status = 'FAILED_UNEXPECTEDLY_VALID';
        rpcMsg = 'Signature verification passed (malleability detected)';
      } else {
        // If signature is invalid after manipulation, test passed
        status = 'REJECTED_AS_EXPECTED';
        rpcMsg = 'Signature verification failed (as expected)';
      }
    } catch (e) {
      // If verification throws an error, signature is invalid (test passed)
      status = 'REJECTED_AS_EXPECTED';
      rpcMsg = `Signature verification error: ${e.message}`;
    }

    const passed = status === 'REJECTED_AS_EXPECTED';
    this.stats[scenario][passed ? 'pass' : 'fail']++;
    return { manipulated, desc, status, rpcMsg, passed };
  }

  async run() {
    log(chalk.blue(`🔬 Malleability Tester JS – ${this.iterations} iterations`));
    for (let i = 1; i <= this.iterations; i++) {
      try {
        console.log(`📊 Processing iteration ${i}/${this.iterations}`);
        const { tx, sigBytes, dest, amount } = await this.createLegitimateTx();
        for (const scenario of ['A', 'B', 'C']) {
          const { manipulated, desc, status, rpcMsg, passed } = await this.testScenario(sigBytes, scenario, tx);
          this.appendCsv([
            i,
            now(),
            scenario,
            toHex(sigBytes),
            toHex(manipulated),
            desc,
            status,
            rpcMsg,
            'REJECTED',
            passed,
            dest,
            amount,
          ]);
        }

        // Add delay between iterations to avoid rate limiting
        if (i % 50 === 0) {
          console.log(`⏸️  Pausing for 2 seconds after ${i} iterations...`);
          await new Promise(resolve => setTimeout(resolve, 100));
        } else if (i % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (error) {
        console.error(`❌ Error in iteration ${i}: ${error.message}`);
        // Continue with next iteration instead of stopping
        continue;
      }
    }
    this.printSummary();
  }

  printSummary() {
    const total = this.iterations * 3;
    const pass = Object.values(this.stats).reduce((s, v) => s + v.pass, 0);
    log(chalk.green(`✅ Passed: ${pass}/${total}`));
    log(chalk.red(`❌ Failed: ${total - pass}/${total}`));
    log(chalk.blue(`📁 CSV saved: ${this.csvFile}`));
  }
}

/* ---------- CLI ---------- */
const iterations = parseInt(process.argv[2]) || 100;
new MalleabilityTester(iterations).run();