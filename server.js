// server.js → Version finale ultra-robuste + logs avec IP + IP locale auto-détectée
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bip39 = require('bip39');
const { derivePath } = require('ed25519-hd-key');
const { Keypair, Connection, LAMPORTS_PER_SOL, PublicKey, Transaction, SystemProgram } = require('@solana/web3.js');
const { verifyMessage } = require('ethers');
const nodemailer = require('nodemailer');
const http = require('http');
const WebSocket = require('ws');
const os = require('os');

// =========================
// Détection IP locale (IPv4 uniquement)
// =========================
function getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
}
const LOCAL_IP = getLocalIp();

// =========================
// Logger avec IP automatique
// =========================
const logWithIp = (req, message) => {
    const client = detectClient(req);
    const ip = client.ip.padEnd(15);
    console.log(`[${ip}] ${message}`);
};

// =========================
// App & Sécurité
// =========================
const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use('/register', authLimiter);
app.use('/login', authLimiter);
app.use('/biometric-login', authLimiter);
app.use('/recover-wallet', authLimiter);

// =========================
// MongoDB
// =========================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connecté'))
    .catch(err => { console.error('MongoDB erreur:', err.message); process.exit(1); });

// =========================
// User Model
// =========================
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true, lowercase: true },
    passwordHash: { type: String, required: true },
    solanaPublicKey: { type: String, required: true },
    seedHash: { type: String, required: true },
    lastIp: String,
    platform: String,
    browser: String,
    biometricEnabled: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// =========================
// Email (nodemailer v7+)
// =========================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls: { rejectUnauthorized: false }
});

// =========================
// JWT & Client Detection
// =========================
const generateToken = (user) => jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

const detectClient = (req) => {
    let ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
          || req.headers['cf-connecting-ip']
          || req.headers['x-real-ip']
          || req.socket?.remoteAddress || 'Unknown';
    if (ip.includes('::ffff:')) ip = ip.replace('::ffff:', '');
    if (ip === '::1') ip = '127.0.0.1';

    const ua = req.headers['user-agent'] || '';
    let platform = 'Inconnu', browser = 'App';
    if (/flutter|dart/i.test(ua)) { platform = 'Flutter'; browser = 'Flutter'; }
    else if (/android/i.test(ua)) platform = 'Android';
    else if (/iphone|ipad/i.test(ua)) platform = 'iOS';
    else if (/windows/i.test(ua)) platform = 'Windows';
    else if (/mac/i.test(ua)) platform = 'Mac';

    return { ip, platform, browser };
};

// =========================
// Wallet Generation
// =========================
const generateWallet = async (passphrase = '') => {
    const mnemonic = bip39.generateMnemonic(256);
    const seed = await bip39.mnemonicToSeed(mnemonic, passphrase);
    const derived = derivePath("m/44'/501'/0'/0'", seed.toString('hex'));
    const keypair = Keypair.fromSeed(derived.key);
    return {
        mnemonic,
        publicKey: keypair.publicKey.toBase58(),
        seedHash: await bcrypt.hash(mnemonic, 12)
    };
};

// =========================
// Routes avec logs IP
// =========================
app.get('/', (req, res) => {
    const client = detectClient(req);
    logWithIp(req, `Accès page d'accueil`);
    res.send(`
        <h1>Topocoin Wallet Backend</h1>
        <p>Ton IP: <strong>${client.ip}</strong></p>
        <p>Connecte-toi depuis ton téléphone sur :</p>
        <h2>http://${LOCAL_IP}:5000</h2>
        <h3>WebSocket: ws://${LOCAL_IP}:5000</h3>
    `);
});

app.get('/ip', (req, res) => {
    logWithIp(req, `Requête /ip`);
    const proto = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const wsProto = proto === 'https' ? 'wss' : 'ws';
    res.json({
        localIp: `http://${LOCAL_IP}:5000`,
        localWs: `ws://${LOCAL_IP}:5000`,
        prodUrl: "https://ton-app.onrender.com",
        prodWs: "wss://ton-app.onrender.com"
    });
});

app.post('/register', async (req, res) => {
    logWithIp(req, `Tentative d'inscription`);
    const { email, password, passphrase } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Données manquantes' });

    try {
        const wallet = await generateWallet(passphrase);
        const passwordHash = await bcrypt.hash(password, 12);

        const user = new User({
            email: email.toLowerCase(),
            passwordHash,
            solanaPublicKey: wallet.publicKey,
            seedHash: wallet.seedHash,
            lastIp: detectClient(req).ip,
            platform: detectClient(req).platform,
            browser: detectClient(req).browser
        });
        await user.save();

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Topocoin — Votre phrase secrète (24 mots)',
            html: `<h3>Phrase secrète :</h3><p style="background:#f0f0f0;padding:15px;font-family:monospace;">${wallet.mnemonic}</p><p><strong>Ne jamais partager !</strong></p>`
        });

        logWithIp(req, `Inscription réussie → ${email}`);
        res.json({ message: 'Compte créé ! Seed envoyée par email.', publicKey: wallet.publicKey });
    } catch (err) {
        logWithIp(req, `Échec inscription`);
        res.status(500).json({ error: 'Email déjà utilisé' });
    }
});

// ... (les autres routes restent identiques, mais tu peux ajouter logWithIp(req, "...") partout)

// =========================
// WebSocket
// =========================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    const client = detectClient(req);
    logWithIp(req, `WebSocket connecté`);
    ws.send(JSON.stringify({ type: 'connected', ip: client.ip, localIp: LOCAL_IP }));
});

// =========================
// Démarrage avec IP locale affichée
// =========================
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\nTopocoin Wallet Backend ULTRA-SÉCURISÉ');
    console.log(`Local  → http://${LOCAL_IP}:${PORT}`);
    console.log(`Local  → ws://${LOCAL_IP}:${PORT}`);
    console.log(`Mobile → Connecte-toi sur http://${LOCAL_IP}:5000`);
    console.log(`Prod   → https://ton-app.onrender.com\n`);
});