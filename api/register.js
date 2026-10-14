const crypto = require('crypto');

const SECRET = '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3';
const CLIENT_ID = '100067';
const USER_AGENT = 'GarenaMSDK/4.0.19P9(SM-S908E; Android 11; en; IN)';
const REGISTER_URL = 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/register';

function randomPassword() {
  return String(Math.floor(1000000000 + Math.random() * 9000000000));
}
function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex').toUpperCase();
}
function hmacSha256Hex(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const password = randomPassword();
  const passwordHash = sha256Hex(password);
  const bodyString = new URLSearchParams({
    password: passwordHash,
    client_type: '2',
    source: '2',
    app_id: CLIENT_ID
  }).toString();
  const signature = hmacSha256Hex(SECRET, bodyString);

  try {
    const resp = await fetch(REGISTER_URL, {
      method: 'POST',
      headers: {
        'User-Agent': USER_AGENT,
        'Authorization': `Signature ${signature}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: bodyString
    });
    if (!resp.ok) {
      const t = await resp.text();
      return res.status(resp.status).json({ error: 'registration_failed', detail: t });
    }
    const data = await resp.json();
    if (!data.uid) return res.status(502).json({ error: 'no_uid', raw: data });
    return res.status(200).json({
      uid: String(data.uid),
      password,
      password_hash: passwordHash
    });
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', detail: err.message });
  }
};
