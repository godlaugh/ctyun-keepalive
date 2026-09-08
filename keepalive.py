# -*- coding: utf-8 -*-
"""
天翼云电脑保活（加密协议版）—— 替代已失效的 CtYun.exe
流程: 登录(自动OCR) -> pageDesktop -> connect -> WebSocket 保活循环
日志写入 keepalive.log，异常自动重连/重登。
"""
import asyncio, base64, hashlib, json, os, random, struct, sys, time, traceback

import msvcrt

# 单实例锁：已运行则直接退出
_lock_f = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "keepalive.lock"), "w")
try:
    msvcrt.locking(_lock_f.fileno(), msvcrt.LK_NBLCK, 1)
except OSError:
    print("已有保活实例在运行，退出", flush=True)
    sys.exit(0)

import ddddocr
import websockets

from ctyun_client import (load, save, make_session, post_json, post_form,
                          get_enc, decode_resp, negotiate,
                          PHONE, PASSWORD, DEVICE_CODE, BASE,
                          VERSION, APP_VERSION, sha256)

KEEPALIVE_SECONDS = 60
LOG = "keepalive.log"
INITIAL_PAYLOAD = base64.b64decode("UkVEUQIAAAACAAAAGgAAAAAAAAABAAEAAAABAAAAEgAAAAkAAAAECAAA")

ocr = ddddocr.DdddOcr(show_ad=False)


def log(msg):
    line = f"[{time.strftime('%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)  # stdout 由 run-loop.bat 重定向进 keepalive.log


# ---------- 保活校验响应（移植 Encryption.cs：RSA-OAEP-SHA1, 空label） ----------
def sha1(b):
    return hashlib.sha1(b).digest()

def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += sha1(seed + struct.pack(">I", counter))
        counter += 1
    return out[:length]

def redq_response(data: bytes) -> bytes:
    buf = data[16:]
    n = int.from_bytes(buf[32:32 + 129], "big")
    e = (buf[163] << 16) | (buf[164] << 8) | buf[165]
    key_len, hlen = 128, 20
    label = b""
    seed = bytearray(os.urandom(hlen))
    db_len = key_len - hlen - 1
    db = bytearray(db_len)
    db[:hlen] = sha1(label)
    db[db_len - len(label) - 1] = 1
    db_mask = mgf1(bytes(seed), db_len)
    for i in range(db_len):
        db[i] ^= db_mask[i]
    seed_mask = mgf1(bytes(db), hlen)
    for i in range(hlen):
        seed[i] ^= seed_mask[i]
    em = b"\x00" + bytes(seed) + bytes(db)
    m = int.from_bytes(em, "big")
    c = pow(m, e, n)
    enc = c.to_bytes(key_len, "big")
    return struct.pack("<I", 1) + enc


# ---------- SendInfo 封包 ----------
def build_sendinfo(msg_type: int, payload: bytes) -> bytes:
    """ToBuffer(isBuildMsg=True)"""
    data_len = len(payload)
    size = 8 + data_len
    buf = struct.pack("<H", msg_type) + struct.pack("<I", size)
    buf += struct.pack("<I", data_len) + struct.pack("<I", 8)
    return buf + payload

def parse_sendinfos(data: bytes):
    out, off = [], 0
    while off + 6 <= len(data):
        t, dlen = struct.unpack_from("<HI", data, off)
        if dlen < 0 or off + 6 + dlen > len(data):
            break
        out.append((t, data[off + 6: off + 6 + dlen]))
        off += 6 + dlen
    return out


# ---------- 登录（自动 OCR 重试） ----------
def ensure_login():
    st = load()
    if st.get("login"):
        return st
    log("需要重新登录，开始自动识别验证码...")
    for attempt in range(1, 16):
        st = load()
        negotiate(st)
        st = load()
        s = make_session(st)
        r = post_json(s, st, "/api/auth/client/genChallengeData", {})
        ch = decode_resp(r)["data"]
        st["challenge"] = ch
        save(st)
        s = make_session(st)
        r = get_enc(s, st, "/api/auth/client/captcha",
                    {"height": "72", "width": "170", "userInfo": PHONE,
                     "mode": "auto", "_t": str(int(time.time() * 1000))})
        code = ocr.classification(r.content)
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
        j = decode_resp(r)
        if j.get("code") == 0:
            st = load()
            st["login"] = j["data"]
            st["cookies"] = s.cookies
            save(st)
            log(f"登录成功（第{attempt}次尝试，OCR={code!r}）")
            return st
        log(f"登录失败[{attempt}] OCR={code!r}: {j.get('msg')}")
        time.sleep(1)
    raise RuntimeError("连续15次登录失败")


def api_with_relogin(fn):
    """调用 API，遇登录失效自动重登后重试一次"""
    st = ensure_login()
    s = make_session(st)
    j = fn(s, st)
    code = j.get("code")
    if code == 0:
        return j["data"]
    if code in (30001, 30002, 30010) or "登录" in str(j.get("msg", "")) or "权限" in str(j.get("msg", "")):
        log(f"登录状态失效(code={code})，重新登录")
        st = load()
        st.pop("login", None)
        save(st)
        st = ensure_login()
        s = make_session(st)
        j = fn(s, st)
        if j.get("code") == 0:
            return j["data"]
    raise RuntimeError(f"API 错误: {j}")


def get_desktops():
    return api_with_relogin(
        lambda s, st: decode_resp(post_json(s, st, "/api/desktop/client/pageDesktop",
            {"getCnt": 20, "desktopTypes": ["1", "2001", "2002", "2003"],
             "sortType": "createTimeV1"})))["desktopList"]


def connect_desktop(desktop_id):
    form = {
        "objId": str(desktop_id), "objType": "0", "osType": "15",
        "deviceId": "60", "vdCommand": "", "ipAddress": "", "macAddress": "",
        "deviceCode": DEVICE_CODE, "deviceName": "Chrome浏览器",
        "deviceType": "60", "deviceModel": "Windows NT 10.0; Win64; x64",
        "appVersion": APP_VERSION, "sysVersion": "Windows NT 10.0; Win64; x64",
        "clientVersion": VERSION,
    }
    return api_with_relogin(
        lambda s, st: decode_resp(post_form(s, st, "/api/desktop/client/connect", form)))


# ---------- WebSocket 保活 ----------
async def keepalive_session(desktop):
    did = desktop["desktopId"]
    dcode = desktop.get("desktopCode", "?")
    info = connect_desktop(did)["desktopInfo"]
    uri = f"wss://{info['clinkLvsOutHost']}/clinkProxy/{did}/MAIN"
    host, _, port = info["clinkLvsOutHost"].partition(":")
    conn_msg = {
        "type": 1, "ssl": 1, "host": host, "port": port or "443",
        "ca": info["caCert"], "cert": info["clientCert"], "key": info["clientKey"],
        "servername": f"{info['host']}:{info['port']}", "oqs": 0,
    }
    login = load()["login"]
    username = login.get("userName") or login.get("userAccount") or PHONE
    userid = login.get("userId")

    async with websockets.connect(uri, subprotocols=["binary"],
                                  origin="https://pc.ctyun.cn",
                                  ping_interval=None) as ws:
        await ws.send(json.dumps(conn_msg, separators=(",", ":")))
        await asyncio.sleep(0.5)
        await ws.send(INITIAL_PAYLOAD)
        log(f"[{dcode}] 连接已就绪，保持 {KEEPALIVE_SECONDS} 秒")
        deadline = time.time() + KEEPALIVE_SECONDS
        while time.time() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=max(1, deadline - time.time()))
            except asyncio.TimeoutError:
                break
            if isinstance(msg, str):
                continue
            if msg[:4].hex().upper() == "52454451":
                await ws.send(redq_response(msg))
                log(f"[{dcode}] 收到保活校验 -> 已响应")
                continue
            for t, payload in parse_sendinfos(msg):
                if t == 103:
                    p = json.dumps({"type": 1, "userName": username,
                                    "userInfo": "", "userId": userid},
                                   separators=(",", ":")).encode()
                    await ws.send(build_sendinfo(118, p))
                    log(f"[{dcode}] 响应 type103 -> 118")


async def main_loop():
    log("=== 保活程序启动 ===")
    while True:
        try:
            desktops = get_desktops()
            log(f"云电脑列表: {[d.get('desktopName') for d in desktops]}")
            if not desktops:
                log("账号下没有云电脑，60秒后重试")
                await asyncio.sleep(60)
                continue
            # 每台云电脑轮流保活（通常只有一台）
            for d in desktops:
                try:
                    await keepalive_session(d)
                except Exception as ex:
                    log(f"[{d.get('desktopCode','?')}] 会话异常: {ex}")
                    await asyncio.sleep(5)
        except Exception:
            log("主循环异常:\n" + traceback.format_exc())
            await asyncio.sleep(30)


if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        pass
