# -*- coding: utf-8 -*-
"""
天翼云电脑网页版协议客户端（含请求体加密）——用于设备绑定
子命令:
  fetch_login_captcha   协商密钥+挑战码+拉登录验证码图(captcha.png)
  login <图形码>        提交登录
  fetch_sms_captcha     拉短信前的图形验证码(sms_captcha.png)
  send_sms <图形码>     发送短信验证码到手机
  bind <短信验证码>     绑定设备
状态保存在 client_state.pkl
"""
import base64, hashlib, json, os, pickle, sys, time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 账号信息外置到 config.json（不纳入 git 备份）
_cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"), encoding="utf-8"))
PHONE = _cfg["phone"]
PASSWORD = _cfg["password"]
DEVICE_CODE = _cfg["deviceCode"]
BASE = "https://desk.ctyun.cn:8810"
VERSION = "204000100"
APP_VERSION = "4.0.1"
STATE = "client_state.pkl"

ZERO_IV = b"\x00" * 16

def aes_enc(text: str, key: str) -> str:
    k = key.encode()
    assert len(k) in (16, 24, 32), f"AES key len={len(k)}"
    pad = 16 - len(text.encode()) % 16
    data = text.encode() + bytes([pad]) * pad
    c = Cipher(algorithms.AES(k), modes.CBC(ZERO_IV)).encryptor()
    return base64.b64encode(c.update(data) + c.finalize()).decode()

def aes_dec(b64: str, key: str) -> str:
    k = key.encode()
    d = Cipher(algorithms.AES(k), modes.CBC(ZERO_IV)).decryptor()
    raw = d.update(base64.b64decode(b64)) + d.finalize()
    return raw[:-raw[-1]].decode()

def md5(x: str) -> str:
    return hashlib.md5(x.encode()).hexdigest()

def sha256(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()

def load():
    try:
        with open(STATE, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return {}

def save(st):
    with open(STATE, "wb") as f:
        pickle.dump(st, f)

def make_session(st):
    s = requests.Session()
    if st.get("cookies"):
        s.cookies = st["cookies"]
    ts = str(int(time.time() * 1000))
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "referer": "https://pc.ctyun.cn/",
        "ctg-devicetype": "60",
        "ctg-devicecode": DEVICE_CODE,
        "ctg-version": VERSION,
        "ctg-requestid": ts,
        "ctg-timestamp": ts,
        "ctg-appmodel": "2",
        "ctg-softwarecode": "2",
    }
    login = st.get("login")
    if login:
        sig = md5(f"60{ts}{login['tenantId']}{ts}{login['userId']}{VERSION}{login['secretKey']}")
        h.update({
            "ctg-userid": str(login["userId"]),
            "ctg-tenantid": str(login["tenantId"]),
            "ctg-signaturestr": sig,
        })
    s.headers.update(h)
    return s

def post_json(s, st, path, payload):
    """POST json，按加密开关加密为 {data: ...}"""
    if st.get("evalue"):
        body = {"data": aes_enc(json.dumps(payload, separators=(",", ":")), st["evalue"])}
        r = s.post(BASE + path, json=body, headers={
            "CTG-REQDATA-ETYPE": "2", "CTG-NEGO-EKEYID": st["eid"]})
    else:
        r = s.post(BASE + path, json=payload)
    return r

def post_form(s, st, path, form):
    """POST form-urlencoded，加密为 eParams=..."""
    if st.get("evalue"):
        ct = aes_enc(json.dumps(form, separators=(",", ":"), ensure_ascii=False), st["evalue"])
        r = s.post(BASE + path, data={"eParams": ct}, headers={
            "CTG-REQDATA-ETYPE": "2", "CTG-NEGO-EKEYID": st["eid"]})
    else:
        r = s.post(BASE + path, data=form)
    return r

def get_enc(s, st, path, params):
    """GET，参数加密为 eUrlParams"""
    if st.get("evalue"):
        from urllib.parse import urlencode
        qs = urlencode(params)
        r = s.get(BASE + path, params={"eUrlParams": aes_enc(qs, st["evalue"])}, headers={
            "CTG-REQDATA-ETYPE": "2", "CTG-NEGO-EKEYID": st["eid"]})
    else:
        r = s.get(BASE + path, params=params)
    return r

def decode_resp(r):
    """响应体若是 {edata: ...} 则解密"""
    j = r.json()
    if isinstance(j, dict) and "edata" in j and "code" not in j:
        st = load()
        return json.loads(aes_dec(j["edata"], st["evalue"]))
    if r.headers.get("ctg-rspdata-etype") == "2" and isinstance(j.get("data"), (dict, str)):
        st = load()
        d = j["data"]
        if isinstance(d, dict) and "edata" in d:
            j["data"] = json.loads(aes_dec(d["edata"], st["evalue"]))
        elif isinstance(d, str):
            j["data"] = json.loads(aes_dec(d, st["evalue"]))
    return j

def negotiate(st):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    cert = base64.b64encode(spki).decode()
    s = make_session(st)
    r = s.post(BASE + "/api/auth/client/negotiationEncKey",
               json={"etype": "2", "certType": "2", "certData": cert})
    print("negotiation:", r.status_code, r.text[:200])
    data = r.json()["data"]
    enc_key, enc_data = data["encKey"], data["encData"]
    raw = base64.b64decode(enc_key)
    n = None
    for pad in (asym_padding.PKCS1v15(),
                asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA512()), algorithm=hashes.SHA512(), label=None),
                asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)):
        try:
            n = priv.decrypt(raw, pad).decode()
            print("RSA 解密成功:", pad.name if hasattr(pad, "name") else pad)
            break
        except Exception:
            continue
    if n is None:
        raise RuntimeError("RSA 解密 encKey 失败")
    info = json.loads(aes_dec(enc_data, n))
    print("密钥协商成功:", {k: (v[:10] + "...") for k, v in info.items()})
    st["eid"], st["evalue"] = info["eid"], info["evalue"]
    save(st)

def cmd_fetch_login_captcha():
    st = load()
    negotiate(st)
    s = make_session(st)
    r = post_json(s, st, "/api/auth/client/genChallengeData", {})
    j = decode_resp(r)
    print("genChallengeData:", json.dumps(j, ensure_ascii=False)[:200])
    st["challenge"] = j["data"]
    st["ts"] = time.time()
    save(st)
    s = make_session(st)
    r = get_enc(s, st, "/api/auth/client/captcha",
                {"height": "72", "width": "170", "userInfo": PHONE, "mode": "auto",
                 "_t": str(int(time.time() * 1000))})
    print("captcha:", r.status_code, r.headers.get("Content-Type"), len(r.content))
    st["captcha_key"] = r.headers.get("CTG-CAPTCHA-KEY", "")
    save(st)
    open("captcha.png", "wb").write(r.content)
    from PIL import Image
    im = Image.open("captcha.png").convert("RGB")
    im.resize((im.width * 3, im.height * 3), Image.LANCZOS).save("captcha_big.png")
    print("验证码已保存 captcha_big.png")

def cmd_login(code):
    st = load()
    ch = st["challenge"]
    if time.time() - st.get("ts", 0) > ch.get("effectiveSeconds", 60):
        print("警告：挑战码可能过期")
    form = {
        "userAccount": PHONE,
        "password": sha256(PASSWORD + ch["challengeCode"]),
        "sha256Password": sha256(sha256(PASSWORD) + ch["challengeCode"]),
        "challengeId": ch["challengeId"],
        "captchaCode": code,
        "deviceCode": DEVICE_CODE,
        "deviceName": "Chrome浏览器",
        "deviceType": "60",
        "deviceModel": "Windows NT 10.0; Win64; x64",
        "appVersion": APP_VERSION,
        "sysVersion": "Windows NT 10.0; Win64; x64",
        "clientVersion": VERSION,
    }
    s = make_session(st)
    r = post_form(s, st, "/api/auth/client/login", form)
    print("login:", r.status_code, r.text[:400])
    j = decode_resp(r)
    if j.get("code") == 0:
        st["login"] = j["data"]
        st["cookies"] = s.cookies
        save(st)
        print("登录成功！userId=", j["data"].get("userId"))

def cmd_fetch_sms_captcha():
    st = load()
    s = make_session(st)
    r = get_enc(s, st, "/api/auth/client/validateCode/captcha",
                {"width": "120", "height": "40", "_t": str(int(time.time() * 1000))})
    print("sms captcha:", r.status_code, r.headers.get("Content-Type"), len(r.content))
    st["sms_captcha_key"] = r.headers.get("CTG-CAPTCHA-KEY", "")
    save(st)
    open("sms_captcha.png", "wb").write(r.content)
    from PIL import Image
    im = Image.open("sms_captcha.png").convert("RGB")
    im.resize((im.width * 4, im.height * 4), Image.LANCZOS).save("sms_captcha_big.png")
    print("短信图形码已保存 sms_captcha_big.png")

def cmd_send_sms(code):
    st = load()
    s = make_session(st)
    r = get_enc(s, st, "/api/cdserv/client/device/getSmsCode",
                {"mobilePhone": PHONE, "captchaCode": code})
    print("getSmsCode:", r.status_code, r.text[:300])
    print("SMS-KEY:", r.headers.get("ctg-sms-key", "")[:40])

def cmd_bind(sms_code):
    st = load()
    s = make_session(st)
    from urllib.parse import quote
    q = (f"verificationCode={sms_code}&deviceName={quote('Chrome浏览器')}"
         f"&deviceCode={DEVICE_CODE}&deviceModel={quote('Windows NT 10.0; Win64; x64')}"
         f"&sysVersion={quote('Windows NT 10.0; Win64; x64')}&appVersion={APP_VERSION}"
         f"&hostName=pc.ctyun.cn&deviceInfo=Win32")
    headers = {}
    if st.get("evalue"):
        headers = {"CTG-REQDATA-ETYPE": "2", "CTG-NEGO-EKEYID": st["eid"]}
    r = s.post(f"{BASE}/api/cdserv/client/device/binding?{q}", headers=headers)
    print("binding:", r.status_code, r.text[:300])
    j = decode_resp(r)
    if j.get("code") == 0:
        print("设备绑定成功！")
        # 同步写出 CtYun.exe 用的 devices 文件
        import os
        os.makedirs("devices", exist_ok=True)
        with open(f"devices/{PHONE}.txt", "w") as f:
            f.write(DEVICE_CODE)

if __name__ == "__main__":
    cmd = sys.argv[1]
    {"fetch_login_captcha": cmd_fetch_login_captcha,
     "login": lambda: cmd_login(sys.argv[2]),
     "fetch_sms_captcha": cmd_fetch_sms_captcha,
     "send_sms": lambda: cmd_send_sms(sys.argv[2]),
     "bind": lambda: cmd_bind(sys.argv[2])}[cmd]()
