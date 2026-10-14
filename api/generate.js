const crypto = require('crypto');

// Garena constants
const AES_KEY = Buffer.from([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56]);
const AES_IV  = Buffer.from([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37]);
const CLIENT_SECRET = '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3';
const APP_ID = 100067;

const OAUTH_REGISTER_URL    = 'https://100067.connect.garena.com/api/v2/oauth/guest:register';
const OAUTH_TOKEN_URL       = 'https://100067.connect.garena.com/oauth/guest/token/grant';
const MAJOR_REGISTER_URL    = 'https://loginbp.ppmainecoonghj.com/MajorRegister';
const NEWBIE_URL            = 'https://loginbp.ppmainecoonghj.com/ChooseNewbieChoice';
const MAJOR_LOGIN_URL       = 'https://loginbp.ppmainecoonghj.com/MajorLogin';
const GENERATE_NICKNAME_URL = 'https://loginbp.ppmainecoonghj.com/GenerateNickname';

const XOR_KEY = [
  0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
  0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30
];

const FIELD_22_HEX = (
  '474752450101010062020000a78910bd098e3ff2e4345d59a31db114ea088f37e32e65' +
  '212ff96621793d9eb78720d0bf2ac95176569765247ada5eb01376b3b9931794a4946' +
  'd76ef8890779f3f2129317e6e1cb2fdcf7b06247cea343b8d4f167eff85a2e1dfe99' +
  'b4583a7e1a155dbe7f7f85cff3b223eb77222ec1228f3ee1ef6ce7f8ca24b00a554' +
  'e497328812f8df74c82d519ae3e3ceab436eb145e8a517089a7cef6a4efb22214b2' +
  'a4b19989b74807584afe5e52825e7ac60e19a596a9bf02d961de6a0ed2515ec6023' +
  'fdb7684d9464b97b21c527ce61b6bee4ef30d20a1fa33a996952d44d44e44f2f86c' +
  '768aaf2a7808ad60f91048dca0207961ba7c2555c48341b30190debc775edb2cee24' +
  '4cf51fca3760ce4388be2db45e80b813b5beb9c784007b7762d7a1e428affc8a3a4' +
  'cd76cbaef648a274297fde33233dccd3f272cb77f39a1affe0365a24954111f768f72' +
  '0e77535af024bea2b2726c3bac992374755c3deacf09235e6865d456e651680d115a' +
  '751a797225eaacdf9a513cf104526e1a32e5296e111a33ae581a63850837921df848' +
  '9adfd41ea895b7cf3f5b2e45d538a6e4f032f590ccbb7daf5fa9c50adadee0799661' +
  '4c3f957bda349e6c484fdf55970d1943ad7955a76671298b6d98b636b69ebde6bc94' +
  'dbd93ac3393a6ae230130445b2d744189167854a5617be2393e7d8fbb5719a1b4754' +
  '1ba466167e3e05a6c244f1301ee2035acf94dffc8adbde747d5cd85e35ead3acc372' +
  'a59c4220e54bf63f9d80485f3de2518495c1d0f78c911d2da595911fd2a1989cf17' +
  'cf3ded5f6c92dea64d675c555c11df92d6c517ca5d0d61a8962f43f76ec7e87596c' +
  '8325ebf9ab0f8e6d2eca33c511ceac6980906ebd68c478665591dcecf788ec6ef34c' +
  'fbe3fcc279c6147c5bf91cd43cdc9704236'
);

// ---------- protobuf ----------
function writeVarint(v) {
  const out = [];
  while (v > 127) { out.push((v & 0x7F) | 0x80); v >>>= 7; }
  out.push(v);
  return Buffer.from(out);
}
function varintField(f, v) { return Buffer.concat([writeVarint((f << 3) | 0), writeVarint(v)]); }
function strField(f, s) {
  const b = Buffer.from(s, 'utf-8');
  return Buffer.concat([writeVarint((f << 3) | 2), writeVarint(b.length), b]);
}
function bytesField(f, b) {
  return Buffer.concat([writeVarint((f << 3) | 2), writeVarint(b.length), b]);
}
function assembleProto(fields) {
  const parts = [];
  for (const k of Object.keys(fields).map(Number).sort((a,b)=>a-b)) {
    const v = fields[k];
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) parts.push(bytesField(k, Buffer.from(v)));
    else if (typeof v === 'string') parts.push(strField(k, v));
    else if (typeof v === 'number') parts.push(varintField(k, v));
  }
  return Buffer.concat(parts);
}

function readVarint(buf, off) {
  let r = 0, s = 0;
  while (true) {
    const b = buf[off++];
    r |= (b & 0x7F) << s;
    if (!(b & 0x80)) break;
    s += 7;
  }
  return [r, off];
}

function parseProto(buf) {
  const out = {};
  let off = 0;
  while (off < buf.length) {
    let tag, w;
    try { [tag, off] = readVarint(buf, off); } catch { break; }
    const f = tag >> 3; w = tag & 0x7;
    if (f === 0) break;
    try {
      if (w === 0) { const [v, o] = readVarint(buf, off); off = o; out[f] = v; }
      else if (w === 2) {
        let ln; [ln, off] = readVarint(buf, off);
        const val = buf.slice(off, off + ln); off += ln;
        // try utf-8, fallback hex
        const s = val.toString('utf-8');
        out[f] = /[\x00-\x08\x0e-\x1f]/.test(s) ? val.toString('hex') : s;
      } else break;
    } catch { break; }
  }
  return out;
}

// ---------- AES-128-CBC ----------
function aesEncrypt(plain) {
  const c = crypto.createCipheriv('aes-128-cbc', AES_KEY, AES_IV);
  return Buffer.concat([c.update(plain), c.final()]);
}
function aesDecrypt(buf) {
  if (!buf || buf.length % 16 !== 0) return buf;
  try {
    const d = crypto.createDecipheriv('aes-128-cbc', AES_KEY, AES_IV);
    return Buffer.concat([d.update(buf), d.final()]);
  } catch { return buf; }
}
function xorOpenId(openId) {
  const b = Buffer.from(openId, 'utf-8');
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[i] ^ XOR_KEY[i % XOR_KEY.length];
  return out;
}

// ---------- helpers ----------
function randomPassword() {
  // 64-char uppercase hex, mirror python's sha256(os.urandom(32)).hexdigest().upper()
  return crypto.randomBytes(32).toString('hex').toUpperCase();
}
function sha256HexUpper(s) { return crypto.createHash('sha256').update(s).digest('hex').toUpperCase(); }
function hmacSha256Hex(key, data) { return crypto.createHmac('sha256', key).update(data).digest('hex'); }

async function post(url, body, headers) {
  const r = await fetch(url, { method: 'POST', headers, body });
  const buf = Buffer.from(await r.arrayBuffer());
  return { status: r.status, buf, text: () => buf.toString('utf-8') };
}

// ---------- 6-step chain ----------
async function step1_register(password) {
  const payload = { app_id: APP_ID, client_type: 2, password, source: 2 };
  const body = JSON.stringify(payload);
  const sig = hmacSha256Hex(CLIENT_SECRET, body);
  const r = await post(OAUTH_REGISTER_URL, body, {
    'User-Agent': 'GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)',
    'Accept': 'application/json',
    'Content-Type': 'application/json; charset=utf-8',
    'Connection': 'Keep-Alive',
    'Authorization': `Signature ${sig}`,
  });
  if (r.status !== 200) throw new Error(`s1 HTTP ${r.status}: ${r.text().slice(0,150)}`);
  const d = JSON.parse(r.text());
  if (d.code !== 0) throw new Error(`s1 code=${d.code} ${d.message || ''}`);
  return String(d.data.uid);
}

async function step2_token(uid, password) {
  const form = new URLSearchParams({
    uid, password, response_type: 'token',
    client_type: '2', client_secret: CLIENT_SECRET, client_id: '100067'
  }).toString();
  const r = await post(OAUTH_TOKEN_URL, form, {
    'User-Agent': 'GarenaMSDK/4.0.30',
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded',
  });
  if (r.status !== 200) throw new Error(`s2 HTTP ${r.status}`);
  const d = JSON.parse(r.text());
  if (!d.access_token || !d.open_id) throw new Error('s2 missing token');
  return { access_token: d.access_token, open_id: d.open_id };
}

async function step3_nickname(open_id) {
  const plain = assembleProto({ 1: 'en', 2: open_id });
  const enc = aesEncrypt(plain);
  const r = await post(GENERATE_NICKNAME_URL, enc, {
    'Accept-Encoding': 'gzip',
    'Authorization': 'Bearer',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': 'loginbp.ppmainecoonghj.com',
    'ReleaseVersion': 'OB55',
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'X-GA': 'v1 1',
    'X-Unity-Version': '2018.4.12f1',
  });
  if (r.status !== 200) throw new Error(`s3 HTTP ${r.status}`);
  const name = r.text().trim();
  if (!name) throw new Error('s3 empty');
  return name;
}

async function step4_major_register(nickname, access_token, open_id, region) {
  const fields = {
    1: nickname, 2: access_token, 3: open_id,
    5: 102000007, 6: 4, 7: 1, 13: 1,
    14: xorOpenId(open_id),
    15: region, 16: 2, 20: '2.133.8', 21: 1,
    22: Buffer.from(FIELD_22_HEX, 'hex'),
  };
  const enc = aesEncrypt(assembleProto(fields));
  const r = await post(MAJOR_REGISTER_URL, enc, {
    'Host': 'loginbp.ppmainecoonghj.com',
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Accept': '*/*',
    'X-GA-SV': String(Math.floor(Date.now()/1000)),
    'Authorization': 'Bearer',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Unity-Version': '2018.4.12f1',
  });
  if (r.status !== 200) throw new Error(`s4 HTTP ${r.status}`);
  const parsed = parseProto(r.buf);
  const aid = parsed[3];
  if (!aid) throw new Error('s4 no account_id');
  return Number(aid);
}

async function step5_newbie(account_id) {
  const plain = assembleProto({ 1: account_id, 2: 1, 3: 3 });
  const enc = aesEncrypt(plain);
  const r = await post(NEWBIE_URL, enc, {
    'Host': 'loginbp.ppmainecoonghj.com',
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Accept': '*/*',
    'X-GA-SV': String(Math.floor(Date.now()/1000)),
    'Authorization': 'Bearer',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Unity-Version': '2018.4.12f1',
  });
  if (r.status !== 200) throw new Error(`s5 HTTP ${r.status}`);
  return true;
}

async function step6_major_login(access_token, open_id, region) {
  const randIp = () => `${1+Math.floor(Math.random()*223)}.${1+Math.floor(Math.random()*255)}.${1+Math.floor(Math.random()*255)}.${1+Math.floor(Math.random()*255)}`;
  const fields = {
    3: new Date().toISOString().replace('T',' ').slice(0,19),
    4: 'free fire', 5: 1, 7: '2.133.9',
    8: 'Android OS 10 / API-29 (QP1A.190711.020/1617006012)',
    9: 'Handheld', 10: 'Vi India', 11: 'WIFI',
    12: 1600, 13: 720, 14: '320',
    15: 'ARM64 FP ASIMD AES | 2301 | 8', 16: 2799,
    17: 'PowerVR Rogue GE8320', 18: 'OpenGL ES 3.2 build 1.11@5425693',
    19: 'Google|9f7d6b8b-b10c-454a-852d-06332cd498eb',
    20: randIp(),
    21: 'en', 22: open_id, 23: '4',
    24: 'Handheld', 25: 'realme RMX2189', 26: region,
    29: access_token, 30: 1,
    41: 'Vi India', 42: 'WIFI',
    57: '1ac4b80ecf0478a44203bf8fac6120f5',
    60: 19799, 61: 2536, 62: 5056, 64: 2768,
    65: 19999, 66: 2536, 67: 19799,
    73: 1,
    74: '/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/lib/arm64',
    76: 2,
    77: '38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/base.apk',
    78: 2, 79: 2, 81: '64', 83: '2019118527',
    86: 'OpenGLES3', 87: 3071, 88: 4, 92: 67920,
    93: 'android_max',
    94: 'KqsHT+UrR1HKqb6+1db+Ofei+NtZr2+hbiBo3yKDL8w+8E3S5qF2IgEEe1fFQFyHRzl4iyHjHp+QsfeLbjJ6+DidTiKxm0ak2uYYa6QR4nAUdlZR',
    95: 111107,
    96: '{"cur_rate":null,"support_etc2":true}',
    97: 1, 98: 1, 99: '4', 100: '4', 102: '',
    104: 83812, 105: 1,
    106: 'https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a',
    107: '1.9393e7b8e53e8aeb',
  };
  const enc = aesEncrypt(assembleProto(fields));
  const r = await post(MAJOR_LOGIN_URL, enc, {
    'Host': 'loginbp.ppmainecoonghj.com',
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Accept': '*/*',
    'X-GA-SV': String(Math.floor(Date.now()/1000)),
    'Authorization': 'Bearer',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55',
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Unity-Version': '2018.4.12f1',
  });
  if (r.status !== 200) throw new Error(`s6 HTTP ${r.status}`);

  const raw = r.buf;
  const candidates = [aesDecrypt(raw), raw.length > 64 ? raw.slice(64) : Buffer.alloc(0), raw];
  for (const buf of candidates) {
    if (!buf.length) continue;
    const parsed = parseProto(buf);
    let jwt = parsed[8];
    if (Buffer.isBuffer(jwt)) jwt = jwt.toString('utf-8');
    if (typeof jwt === 'string' && jwt.startsWith('eyJ') && jwt.split('.').length === 3) {
      const sixteens = [];
      for (const f of Object.keys(parsed).map(Number).sort((a,b)=>a-b)) {
        const v = parsed[f];
        if (Buffer.isBuffer(v) && v.length === 16) sixteens.push(v);
        else if (typeof v === 'string' && /^[0-9a-f]{32}$/i.test(v)) sixteens.push(Buffer.from(v, 'hex'));
      }
      const k = sixteens.length >= 2 ? sixteens[sixteens.length - 2] : AES_KEY;
      const i_ = sixteens.length >= 2 ? sixteens[sixteens.length - 1] : AES_IV;
      return { jwt, session_key: k.toString('hex'), session_iv: i_.toString('hex') };
    }
  }
  throw new Error('s6 no JWT');
}

// ---------- handler ----------
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const region = (req.query.region || 'ID').toString().toUpperCase();
  const t0 = Date.now();
  const password = randomPassword();
  const passwordHash = sha256HexUpper(password);

  const result = { region, created_at: new Date().toISOString().replace('T',' ').slice(0,19) };
  try {
    const uid = await step1_register(passwordHash);
    result.uid = uid;

    const { access_token, open_id } = await step2_token(uid, passwordHash);
    result.access_token = access_token;
    result.open_id = open_id;

    const nickname = await step3_nickname(open_id);
    result.nickname = nickname;

    const account_id = await step4_major_register(nickname, access_token, open_id, region);
    result.account_id = account_id;

    await step5_newbie(account_id);

    const { jwt, session_key, session_iv } = await step6_major_login(access_token, open_id, region);
    result.jwt = jwt;
    result.session_key = session_key;
    result.session_iv = session_iv;

    result.password = password;  // note: raw upper-hex, same as python output
    result.ok = true;
    result.elapsed_ms = Date.now() - t0;
    return res.status(200).json(result);
  } catch (e) {
    result.ok = false;
    result.error = e.message;
    result.elapsed_ms = Date.now() - t0;
    return res.status(200).json(result);
  }
};
