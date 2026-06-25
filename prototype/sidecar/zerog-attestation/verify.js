#!/usr/bin/env node
// sinabro W2-B — 0G Compute TEE attestation verifier (read-only / keyless / no funds).
//
// The "TEE-verified Compute" gate: prove a 0G Compute provider runs genuine TEE-attested
// inference. Uses the SDK's READ-ONLY broker (createZGComputeNetworkReadOnlyBroker — "WITHOUT
// wallet connection"), so there is NO key, NO funds, NO on-chain write — PD-6 custody is
// untouched. If verifyService is not exposed on the read-only broker, it falls back to an
// EPHEMERAL, UNFUNDED wallet (balance 0 ⇒ structurally cannot spend; never persisted).
//
// Output: ONE line of JSON to stdout. Usage: node verify.js [providerAddress]
'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');

const RPC = process.env.ZEROG_TESTNET_RPC || 'https://evmrpc-testnet.0g.ai';
const CHAIN_ID = 16602; // 0G Galileo testnet

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// ServiceStructOutput may be a plain object {provider,...} or an ethers Result tuple.
function providerOf(svc) {
  if (!svc) return null;
  if (typeof svc.provider === 'string') return svc.provider;
  if (Array.isArray(svc) && typeof svc[0] === 'string') return svc[0];
  return null;
}

function modelOf(svc) {
  if (!svc) return null;
  if (typeof svc.model === 'string') return svc.model;
  return null;
}

async function main() {
  const sdk = require('@0gfoundation/0g-compute-ts-sdk');
  const explicit =
    process.argv[2] && process.argv[2].startsWith('0x') ? process.argv[2] : null;
  const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zerog-attest-'));

  // 1. read-only broker (NO wallet) — list providers from public chain data.
  const ro = await sdk.createZGComputeNetworkReadOnlyBroker(RPC, CHAIN_ID);
  const services = await ro.inference.listService();
  const first = services && services.length ? services[0] : null;
  const provider = explicit || providerOf(first);
  if (!provider) {
    out({ ok: false, error: 'no provider found', serviceCount: (services || []).length });
    process.exit(1);
  }

  // 2. resolve a verifyService entry point — prefer the wallet-free read-only broker.
  let mode = null;
  let verifyOn = null;
  if (typeof ro.verifyService === 'function') {
    mode = 'readonly';
    verifyOn = ro;
  } else if (ro.inference && typeof ro.inference.verifyService === 'function') {
    mode = 'readonly.inference';
    verifyOn = ro.inference;
  } else {
    // fallback: an EPHEMERAL, UNFUNDED wallet (balance 0 ⇒ cannot spend; never saved).
    const { ethers } = require('ethers');
    const provider0g = new ethers.JsonRpcProvider(RPC);
    const wallet = ethers.Wallet.createRandom().connect(provider0g);
    const full = await sdk.createZGComputeNetworkBroker(wallet);
    mode = 'ephemeral-wallet';
    verifyOn = typeof full.verifyService === 'function' ? full : full.inference;
  }

  // 3. verify the provider's TEE attestation.
  const steps = [];
  const result = await verifyOn.verifyService(provider, reportDir, (s) => {
    try {
      steps.push(typeof s === 'string' ? s : JSON.stringify(s));
    } catch (_e) {
      steps.push('[step]');
    }
  });

  const ok = !!(result && (result.success === true || result.valid === true));
  out({
    ok,
    mode,
    provider,
    model: modelOf(first),
    serviceCount: (services || []).length,
    rpc: RPC,
    chainId: CHAIN_ID,
    verification: result,
    steps: steps.slice(0, 60),
    reportDir,
  });
}

main().catch((e) => {
  out({ ok: false, error: String((e && e.message) || e) });
  process.exit(1);
});
