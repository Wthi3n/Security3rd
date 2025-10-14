'use strict';

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// ====== Load keys từ ENV (không commit key vào repo) ======
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM; // đặt trong Secrets
if (!PRIVATE_KEY_PEM) {
  console.error('Missing PRIVATE_KEY_PEM env. Provide RSA private key PEM via secrets.');
  process.exit(1);
}

// Tạo đối tượng key và derive public key
const privateKeyObj = crypto.createPrivateKey({
  key: PRIVATE_KEY_PEM,
  format: 'pem'
});
const publicKeyObj = crypto.createPublicKey(privateKeyObj);
const PUBLIC_KEY_PEM = publicKeyObj.export({ type: 'spki', format: 'pem' }).toString('utf8');

// ====== In-memory store (thay bằng DB/Redis trong production) ======
const challenges = new Map(); // challengeId -> { nonce, expiresAt, appId }
const devices = new Map();    // deviceId -> { pubKeyPEM, registeredAt, revoked }
const revokedJTIs = new Set();

// Rate limit cơ bản
const limiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use(limiter);

// Helpers
function makeId(n = 12) { return crypto.randomBytes(n).toString('base64url'); }
function makeChallenge() { return crypto.randomBytes(32).toString('base64url'); }

// ====== Endpoints ======

// 1) Lấy challenge
// GET /challenge?appid=com.your.app
app.get('/challenge', (req, res) => {
  const appId = req.query.appid || req.headers['x-app-id'];
  if (!appId) return res.status(400).json({ error: 'missing appid' });

  const challengeId = makeId(12);
  const nonce = makeChallenge();
  const expiresAt = Date.now() + 2 * 60 * 1000; // 2 phút
  challenges.set(challengeId, { nonce, expiresAt, appId });

  return res.json({ challengeId, nonce });
});

// 2) Xác thực attestation + assertion (PLACEHOLDER)
// TODO: Implement chuẩn Apple App Attest verification.
async function verifyAttestation({ attestationObjectBase64, assertionBase64, challengeNonce, appId }) {
  // Thực tế: xác minh attestation với Apple, trích public key, verify chữ ký assertion trên nonce.
  // Demo: giả thành công.
  const deviceId = 'dev-' + crypto.randomBytes(8).toString('hex');
  return { ok: true, deviceId, pubKeyPEM: null };
}

// 3) Đăng ký & phát JWT ngắn hạn
// POST /register  body: { challengeId, attestationObject, assertion }
app.post('/register', async (req, res) => {
  try {
    const { challengeId, attestationObject, assertion } = req.body || {};
    if (!challengeId || !attestationObject || !assertion) {
      return res.status(400).json({ error: 'missing params' });
    }

    const entry = challenges.get(challengeId);
    if (!entry || entry.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'invalid_or_expired_challenge' });
    }

    const result = await verifyAttestation({
      attestationObjectBase64: attestationObject,
      assertionBase64: assertion,
      challengeNonce: entry.nonce,
      appId: entry.appId
    });

    if (!result.ok) return res.status(403).json({ error: 'attestation_failed' });

    const deviceId = result.deviceId;
    devices.set(deviceId, { pubKeyPEM: result.pubKeyPEM || null, registeredAt: Date.now(), revoked: false });

    const jti = makeId(8);
    const token = jwt.sign(
      { sub: deviceId, app: entry.appId, jti },
      PRIVATE_KEY_PEM,
      { algorithm: 'RS256', expiresIn: '5m' }
    );

    challenges.delete(challengeId);
    return res.json({ token, expiresIn: 5 * 60, deviceId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// 4) Endpoint bảo vệ bằng JWT
app.get('/protected/resource', (req, res) => {
  const auth = (req.headers.authorization || '').trim();
  const m = auth.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ error: 'missing_token' });

  const token = m[1];
  try {
    const payload = jwt.verify(token, PUBLIC_KEY_PEM, { algorithms: ['RS256'] });
    if (revokedJTIs.has(payload.jti)) return res.status(401).json({ error: 'revoked' });

    const dev = devices.get(payload.sub);
    if (!dev || dev.revoked) return res.status(401).json({ error: 'device_revoked' });

    return res.json({ secret: 'SERVER_SIDE_SECRET_PLACEHOLDER' });
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// 5) Revoke (admin)
app.post('/admin/revoke', (req, res) => {
  const { jti, deviceId } = req.body || {};
  if (jti) revokedJTIs.add(jti);
  if (deviceId && devices.has(deviceId)) devices.get(deviceId).revoked = true;
  return res.json({ ok: true });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth server listening on ${PORT}`));
