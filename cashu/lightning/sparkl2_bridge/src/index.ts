import express from 'express';
import cors from 'cors';
import { SparkWallet } from '@buildonspark/spark-sdk';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8426;

let sparkWallet: SparkWallet | null = null;

app.post('/init', async (req, res) => {
    try {
        const { seed, network } = req.body;
        if (sparkWallet) {
            res.json({ message: "Already initialized" });
            return;
        }

        let seedInput: Uint8Array | string = seed;
        if (/^[0-9a-fA-F]+$/.test(seed) && seed.length >= 32) {
            seedInput = new Uint8Array(Buffer.from(seed, 'hex'));
        }

        const net = (network || 'TESTNET') as any;
        console.log(`Initializing SparkWallet on ${net}...`);
        
        const { wallet } = await SparkWallet.initialize({
            mnemonicOrSeed: seedInput,
            options: { network: net }
        });
        sparkWallet = wallet;
        console.log(`SparkWallet initialized successfully! Address: ${await wallet.getSparkAddress()}`);
        res.json({ status: "ok" });
    } catch (error: any) {
        console.error("Init error:", error);
        res.status(500).json({ error: error.message });
    }
});

const requireInit = (req: any, res: any, next: any) => {
    if (!sparkWallet) {
        res.status(400).json({ error: "Wallet not initialized" });
        return;
    }
    next();
};

app.get('/status', requireInit, async (req, res) => {
    try {
        const balance = await sparkWallet!.getBalance();
        res.json({ balanceSats: Number(balance.balance) });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/invoice', requireInit, async (req, res) => {
    try {
        const { amountSats, memo, descriptionHash } = req.body;
        
        const request = await sparkWallet!.createLightningInvoice({
            amountSats: parseInt(amountSats),
            memo,
            descriptionHash
        });
        
        res.json({
            id: request.id,
            invoice: request.invoice.encodedInvoice,
            paymentHash: request.invoice.paymentHash
        });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/pay', requireInit, async (req, res) => {
    try {
        const { invoice, maxFeeSats } = req.body;
        
        const result = await sparkWallet!.payLightningInvoice({
            invoice,
            maxFeeSats: Number(maxFeeSats)
        });
        
        res.json({
            id: result.id,
            status: result.status
        });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/stream', requireInit, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const pingInterval = setInterval(() => {
        res.write(': keepalive\n\n');
    }, 25000);

    const handleEvent = (event: any) => {
        // Forward incoming transfer/deposit events as 'inv-paid' so the mint can process them
        res.write(`event: inv-paid\ndata: ${JSON.stringify(event)}\n\n`);
    };

    // Subscribe to the correct Spark SDK events for incoming funds
    sparkWallet!.on('transfer:claimed', handleEvent);
    sparkWallet!.on('deposit:confirmed', handleEvent);

    req.on('close', () => {
        clearInterval(pingInterval);
        sparkWallet!.off('transfer:claimed', handleEvent);
        sparkWallet!.off('deposit:confirmed', handleEvent);
    });
});

app.get('/invoice/status/:id', requireInit, async (req, res) => {
    try {
        const id = req.params.id;
        const request = await (sparkWallet! as any).getLightningReceiveRequest(id);
        if (request) {
            res.json({
                status: request.status,
                paymentHash: request.invoice.paymentHash
            });
            return;
        }
        res.json({ status: 'unknown' });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});



app.get('/pay/status/:id', requireInit, async (req, res) => {
    try {
        const id = req.params.id;
        const reqState = await sparkWallet!.getLightningSendRequest(id);
        if (reqState) {
            const anyReq = reqState as any;
            let feeSats = anyReq.feeSats;
            if (anyReq.fee && anyReq.fee.originalValue) {
                // If it's a CurrencyAmount object, Spark fee is usually in msats, so divide by 1000
                feeSats = anyReq.fee.originalValue / 1000;
            } else if (typeof anyReq.fee === 'number') {
                feeSats = anyReq.fee;
            }

            res.json({
                status: reqState.status,
                preimage: anyReq.preimage || anyReq.paymentPreimage,
                feeSats: feeSats
            });
            return;
        }
        res.json({ status: 'unknown' });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/pay/quote', requireInit, async (req, res) => {
    try {
        const { invoice } = req.body;
        const estimate = await sparkWallet!.getLightningSendFeeEstimate({ encodedInvoice: invoice });
        res.json({ feeSats: estimate });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});


app.listen(PORT, () => {
    console.log(`Spark L2 Bridge running on port ${PORT}`);
});
