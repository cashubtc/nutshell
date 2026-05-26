# Spark L2 Bridge for Nutshell

This directory contains a Node.js sidecar service that wraps the official `@buildonspark/spark-sdk` to provide a Spark L2 wallet backend for Nutshell.

## Prerequisites
- Node.js (v18+)
- npm

## Setup
Run the following command to install dependencies:
```bash
npm install
```

Nutshell will automatically try to start the bridge process via `npm start` if it is not already running.

Alternatively, you can start it manually:
```bash
npm start
```

## Configuration
In your `.env` file, enable the backend by setting:
```env
MINT_BACKEND_BOLT11_SAT=SparkL2Wallet
MINT_SPARK_NETWORK=TESTNET # or MAINNET
```

Nutshell will automatically POST your `MINT_PRIVATE_KEY` to the bridge to initialize the deterministic wallet seed.
