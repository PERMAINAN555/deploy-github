from http.server import BaseHTTPRequestHandler
import json, os, time, random, hashlib, hmac, urllib.parse
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ CONSTANTS ============
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
APP_ID = 100067

REG_URL   = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
TOK_URL   = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJREG_URL = "https://loginbp.ppmainecoonghj.com/MajorRegister"
NEWBIE_URL = "https://loginbp.ppmainecoonghj.com/ChooseNewbieChoice"
MAJLOG_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"
NICK_URL   = "https://loginbp.ppmainecoonghj.com/GenerateNickname"

XOR_KEY = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
           0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]

FIELD_22_HEX = (
    "474752450101010062020000a78910bd098e3ff2e4345d59a31db114ea088f37e32e65"
    "212ff96621793d9eb78720d0bf2ac95176569765247ada5eb01376b3b9931794a4946"
    "d76ef8890779f3f2129317e6e1cb2fdcf7b06247cea343b8d4f167eff85a2e1dfe99"
    "b4583a7e1a155dbe7f7f85cff3b223eb77222ec1228f3ee1ef6ce7f8ca24b00a554"
    "e497328812f8df74c82d519ae3e3ceab436eb145e8a517089a7cef6a4efb22214b2"
    "a4b19989b74807584afe5e52825e7ac60e19a596a9bf02d961de6a0ed2515ec6023"
    "fdb7684d9464b97b21c527ce61b6bee4ef30d20a1fa33a996952d44d44e44f2f86c"
    "768aaf2a7808ad60f91048dca0207961ba7c2555c48341b30190debc775edb2cee24"
    "4cf51fca3760ce4388be2db45e80b813b5beb9c784007b7762d7a1e428affc8a3a4"
    "cd76cbaef648a274297fde33233dccd3f272cb77f39a1affe0365a24954111f768f72"
    "0e77535af024bea2b2726c3bac992374755c3deacf09235e6865d456e651680d115a"
    "751a797225eaacdf9a513cf104526e1a32e5296e111a33ae581a63850837921df848"
    "9adfd41ea895b7cf3f5b2e45d538a6e4f032f590ccbb7daf5fa9c50adadee0799661"
    "4c3f957bda349e6c484fdf55970d1943ad7955a76671298b6d98b636b69ebde6bc94"
    "dbd93ac3393a6ae230130445b2d744189167854a5617be2393e7d8fbb5719a1b4754"
    "1ba466167e3e05a6c244f1301ee2035acf94dffc8adbde747d5cd85e35ead3acc372"
    "a59c4220e54bf63f9d80485f3de2518495c1d0f78c911d2da595911fd2a1989cf17"
    "cf3ded5f6c92dea64d675c555c11df92d6c517ca5d0d61a8962f43f76ec7e87596c"
    "8325ebf9ab0f8e6d2eca33c511ceac6980906ebd68c478665591dcecf788ec6ef34c"
    "fbe3fcc279c6147c5bf91cd43cdc9704236"
)

# ============ PROTOBUF ============
def wv(v):
    o = []
    while v > 127:
        o.append((v & 0x7F) | 0x80); v >>= 7
    o.append(v); return bytes(o)

def assemble(fields):
    d = bytearray()
    for k, v in fields.items():
        if isinstance(v, int):
            d += wv((k << 3) | 0) + wv(v)
        elif isinstance(v, str):
            b = v.encode("utf-8")
            d += wv((k << 3) | 2) + wv(len(b)) + b
        elif isinstance(v, bytes):
            d += wv((k << 3) | 2) + wv(len(v)) + v
    return bytes(d)

def rv(data, off):
    r, s = 0, 0
    while True:
        b = data[off]; off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, off

def pproto(data):
    out = {}; off = 0
    while off < len(data):
        try: tag, off = rv(data, off)
        except: break
        f, w = tag >> 3, tag & 7
        if not f: break
        try:
            if w == 0:
                v, off = rv(data, off); out[f] = v
            elif w == 2:
                ln, off = rv(data, off)
                val = data[off:off+ln]; off += ln
                try: out[f] = val.decode("utf-8")
                except: out[f] = val.hex()
            else: break
        except: break
    return out

# ============ AES ============
def aenc(p): return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(p, 16))
def adec(c):
    if not c or len(c) % 16: return c
    try:
        try: return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(c), 16)
        except ValueError: return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(c)
    except: return c

def xor_oid(oid):
    b = oid.encode("utf-8")
    return bytes(x ^ XOR_KEY[i % len(XOR_KEY)] for i, x in enumerate(b))

# ============ STEPS ============
def step1(session, password):
    payload = {"app_id": APP_ID, "client_type": 2, "password": password, "source": 2}
    body = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(CLIENT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    r = session.post(REG_URL, data=body, headers={
        "User-Agent": "GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
        "Authorization": f"Signature {sig}",
    }, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"s1 HTTP {r.status_code}: {r.text[:100]}")
    d = r.json()
    if d.get("code") != 0:
        raise RuntimeError(f"s1 code={d.get('code')}")
    return str(d["data"]["uid"])

def step2(session, uid, password):
    payload = {"uid": uid, "password": password, "response_type": "token",
               "client_type": "2", "client_secret": CLIENT_SECRET, "client_id": "100067"}
    r = session.post(TOK_URL, data=payload, headers={
        "User-Agent": "GarenaMSDK/4.0.30",
        "Accept": "application/json",
        "Connection": "Keep-Alive",
    }, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"s2 HTTP {r.status_code}")
    d = r.json()
    if not d.get("access_token") or not d.get("open_id"):
        raise RuntimeError("s2 missing token")
    return d["access_token"], d["open_id"]

def step3(session, open_id):
    enc = aenc(assemble({1: "en", 2: open_id}))
    r = session.post(NICK_URL, data=enc, headers={
        "Authorization": "Bearer",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": NICK_URL.split("/")[2],
        "ReleaseVersion": "OB55",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.12f1",
    }, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"s3 HTTP {r.status_code}")
    n = r.text.strip()
    if not n: raise RuntimeError("s3 empty")
    return n

def step4(session, nickname, at, oid, region):
    fields = {1: nickname, 2: at, 3: oid, 5: 102000007, 6: 4, 7: 1, 13: 1,
              14: xor_oid(oid), 15: region, 16: 2, 20: "2.133.8", 21: 1,
              22: bytes.fromhex(FIELD_22_HEX)}
    enc = aenc(assemble(fields))
    r = session.post(MAJREG_URL, data=enc, headers={
        "Host": MAJREG_URL.split("/")[2],
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Content-Length": str(len(enc)),
    }, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"s4 HTTP {r.status_code}")
    p = pproto(r.content)
    aid = p.get(3)
    if not aid: raise RuntimeError("s4 no account_id")
    return int(aid)

def step5(session, aid):
    enc = aenc(assemble({1: int(aid), 2: 1, 3: 3}))
    r = session.post(NEWBIE_URL, data=enc, headers={
        "Host": "loginbp.ppmainecoonghj.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }, timeout=30, verify=False)
    if r.status_code != 200:
        raise RuntimeError(f"s5 HTTP {r.status_code}")

def step6(session, at, oid, region, platform="4"):
    fields = {
        3: time.strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire", 5: 1, 7: "2.133.9",
        8: "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
        9: "Handheld", 10: "Vi India", 11: "WIFI",
        12: 1600, 13: 720, 14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8", 16: 2799,
        17: "PowerVR Rogue GE8320", 18: "OpenGL ES 3.2 build 1.11@5425693",
        19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
        20: f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        21: "en", 22: oid, 23: str(platform),
        24: "Handheld", 25: "realme RMX2189", 26: region,
        29: at, 30: 1, 41: "Vi India", 42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 19799, 61: 2536, 62: 5056, 64: 2768,
        65: 19999, 66: 2536, 67: 19799, 73: 1,
        74: "/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/lib/arm64", 76: 2,
        77: "38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/base.apk",
        78: 2, 79: 2, 81: "64", 83: "2019118527",
        86: "OpenGLES3", 87: 3071, 88: 4, 92: 67920, 93: "android_max",
        94: "KqsHT+UrR1HKqb6+1db+Ofei+NtZr2+hbiBo3yKDL8w+8E3S5qF2IgEEe1fFQFyHRzl4iyHjHp+QsfeLbjJ6+DidTiKxm0ak2uYYa6QR4nAUdlZR",
        95: 111107, 96: '{"cur_rate":null,"support_etc2":true}',
        97: 1, 98: 1, 99: "4", 100: "4", 102: "",
        104: 83812, 105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.9393e7b8e53e8aeb",
    }
    enc = aenc(assemble(fields))
    r = session.post(MAJLOG_URL, data=enc, headers={
        "Host": "loginbp.ppmainecoonghj.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Content-Length": str(len(enc)),
    }, timeout=30, verify=False)
    if r.status_code != 200:
        raise RuntimeError(f"s6 HTTP {r.status_code}")
    raw = r.content
    for buf in (adec(raw), raw[64:] if len(raw) > 64 else b"", raw):
        if not buf: continue
        try: p = pproto(buf)
        except: continue
        jwt = p.get(8)
        if isinstance(jwt, bytes):
            try: jwt = jwt.decode("utf-8", "ignore")
            except: jwt = ""
        if isinstance(jwt, str) and jwt.startswith("eyJ") and jwt.count(".") == 2:
            six = []
            for fnum in sorted(p.keys()):
                v = p[fnum]
                for val in (v if isinstance(v, list) else [v]):
                    if isinstance(val, (bytes, bytearray)) and len(val) == 16:
                        six.append(bytes(val))
            k = six[-2] if len(six) >= 2 else AES_KEY
            iv = six[-1] if len(six) >= 2 else AES_IV
            return jwt, k.hex(), iv.hex()
    raise RuntimeError("s6 no JWT")

# ============ MAIN ============
def generate_account(region="ID"):
    session = requests.Session()
    session.verify = False
    password = hashlib.sha256(os.urandom(32)).hexdigest().upper()

    uid = step1(session, password)
    at, oid = step2(session, uid, password)
    nickname = step3(session, oid)
    aid = step4(session, nickname, at, oid, region)
    try: step5(session, aid)
    except: pass
    jwt, sk, siv = step6(session, at, oid, region, "4")

    return {
        "uid": uid, "password": password, "nickname": nickname,
        "open_id": oid, "access_token": at, "account_id": aid,
        "region": region, "jwt": jwt,
        "session_key": sk, "session_iv": siv,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        region = "ID"
        try:
            q = urllib.parse.urlparse(self.path).query
            p = urllib.parse.parse_qs(q)
            region = p.get("region", ["ID"])[0].upper()
        except: pass

        result = {"region": region, "ok": False}
        try:
            t0 = time.time()
            acc = generate_account(region)
            result.update(acc)
            result["ok"] = True
            result["elapsed_ms"] = int((time.time() - t0) * 1000)
        except Exception as e:
            result["error"] = str(e)

        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
