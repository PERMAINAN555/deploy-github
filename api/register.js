const crypto = require('crypto');

const SECRET = '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3';
const CLIENT_ID = '100067';
const USER_AGENT = 'GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)';

const PATHS = [
  'https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest:register',
  'https://ffmconnect.live.gop.garenanow.com/oauth/guest/register',
  'https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/register',
];

function randomPassword() {
  return String(Math.floor(1000000000 + Math.random() * 9000000000));
}
function sha256HexUpper(i) {
  return crypto.createHash('sha256').update(i).digest('hex').toUpperCase();
}
function hmacHex(k, d, upper) {
  const h = crypto.createHmac('sha256', k).update(d).digest('hex');
  return upper ? h.toUpperCase() : h;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const password = randomPassword();
  const passwordHash = sha256HexUpper(password);

  // Variant 1: form-urlencoded body + lowercase sig (ffapis style)
  const formBody = new URLSearchParams({
    password: passwordHash, client_type: '2', source: '2', app_id: CLIENT_ID
  }).toString();
  const sigLower = hmacHex(SECRET, formBody, false);

  // Variant 2: form-urlencoded + uppercase sig (my old style)
  const sigUpper = hmacHex(SECRET, formBody, true);

  // Variant 3: JSON body (v2 pattern from token:grant)
  const jsonBody = JSON.stringify({
    client_id: parseInt(CLIENT_ID),
    client_secret: SECRET,
    client_type: 2,
    password: passwordHash,
    response_type: 'token'
  });

  const attempts = [];
  for (const url of PATHS) {
    for (const [label, headers, body] of [
      ['form+lower', { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Signature ${sigLower}` }, formBody],
      ['form+upper', { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Signature ${sigUpper}` }, formBody],
      ['json+lower', { 'Content-Type': 'application/json; charset=utf-8', 'Authorization': `Signature ${sigLower}` }, jsonBody],
      ['json+upper', { 'Content-Type': 'application/json; charset=utf-8', 'Authorization': `Signature ${sigUpper}` }, jsonBody],
    ]) {
      try {
        const resp = await fetch(url, {
          method: 'POST',
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': 'application/json',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            ...headers
          },
          body
        });
        const text = await resp.text();
        let parsed = null;
        try { parsed = JSON.parse(text); } catch {}
        const uid = parsed && (parsed.uid || (parsed.data && parsed.data.uid));
        attempts.push({ url: url.split('/').slice(-2).join('/'), variant: label, status: resp.status, uid: uid || null, body: text.slice(0, 200) });
        if (resp.ok && uid) {
          return res.status(200).json({
            uid: String(uid),
            password,
            password_hash: passwordHash,
            variant_used: label,
            path_used: url,
            all_attempts: attempts
          });
        }
      } catch (e) {
        attempts.push({ url, variant: label, error: e.message });
      }
    }
  }

  return res.status(200).json({ error: 'all_variants_failed', attempts });
};
