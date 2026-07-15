#!/usr/bin/env python3
"""Opt-in ShadowsocksR TCP/UDP interoperability matrix.

The external server is never vendored or linked into Xray. Point
SSR_PYTHON_DIR at a checkout of EthereumD/ShadowsocksRR at the pinned commit,
and XRAY_BINARY at a freshly built Xray binary.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

PINNED_COMMIT = "1dbffcb0712978857ef2a6d2d617e01bf585a296"
PROTOCOLS = [
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d",
    "auth_chain_e", "auth_chain_f", "auth_akarin_rand", "auth_akarin_spec_a",
]
OBFS = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth"]
CIPHER_SAMPLES = ["none", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "bf-cfb"]


def pick_port(sock_type=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def echo_servers():
    port = pick_port()

    def tcp():
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen()
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=echo_conn, args=(conn,), daemon=True).start()

    def echo_conn(conn):
        with conn:
            while True:
                data = conn.recv(65535)
                if not data:
                    return
                conn.sendall(data)

    def udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        while True:
            data, address = sock.recvfrom(65535)
            sock.sendto(data, address)

    threading.Thread(target=tcp, daemon=True).start()
    threading.Thread(target=udp, daemon=True).start()
    return port


def stop(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def wait_tcp(port, proc, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("process exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not become ready")


def exchange(inbound_port, label):
    payload = ("tcp:" + label).encode()
    with socket.create_connection(("127.0.0.1", inbound_port), 3) as conn:
        conn.settimeout(5)
        conn.sendall(payload)
        received = conn.recv(len(payload))
    if received != payload:
        raise RuntimeError(f"TCP mismatch: {received!r}")

    payload = ("udp:" + label).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(5)
        conn.sendto(payload, ("127.0.0.1", inbound_port))
        received, _ = conn.recvfrom(65535)
    if received != payload:
        raise RuntimeError(f"UDP mismatch: {received!r}")


def run_case(root, xray, python_dir, echo_port, method, protocol, obfs):
    ssr_port, inbound_port = pick_port(), pick_port()
    server_config = {
        "server": "127.0.0.1", "server_port": ssr_port,
        "password": "interop-secret", "method": method,
        "protocol": protocol, "protocol_param": "",
        "obfs": obfs, "obfs_param": "",
        "timeout": 60, "udp_timeout": 60, "dns_ipv6": False,
        "connect_verbose_info": 0, "fast_open": False, "forbidden_ip": "",
    }
    xray_config = {
        "inbounds": [{"listen": "127.0.0.1", "port": inbound_port,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": echo_port,
                                   "network": "tcp,udp"}}],
        "outbounds": [{"protocol": "shadowsocksr", "settings": {
            "address": "127.0.0.1", "port": ssr_port, "method": method,
            "password": "interop-secret", "protocol": protocol, "obfs": obfs,
            "obfsParam": "example.com" if obfs == "tls1.2_ticket_auth" else "",
        }}],
    }
    server_json, xray_json = root / "server.json", root / "xray.json"
    server_json.write_text(json.dumps(server_config), encoding="utf-8")
    xray_json.write_text(json.dumps(xray_config), encoding="utf-8")
    wrapper = root / "server_wrapper.py"
    wrapper.write_text("""
import collections, collections.abc, json, os, signal, sys, time
collections.MutableMapping = collections.abc.MutableMapping
os.environ['OPENSSL_CONF'] = sys.argv[3]
sys.path.insert(0, sys.argv[1])
sys.argv = ['server.py', '-c', sys.argv[2]]
from server_pool import ServerPool
from shadowsocks.obfsplugin import auth_chain

# The pinned server targets Python 2. Its chain-f implementation constructs a
# byte string with chr(), which Python 3 otherwise re-encodes as UTF-8. Keep the
# original one-byte semantics so the external process exercises the protocol,
# not a Python-version artifact.
def chain_f_init_data_size(self, key):
    random = auth_chain.xorshift128plus()
    new_key = bytearray(key)
    for i, value in enumerate(self.key_change_datetime_key_bytes):
        new_key[i] ^= value
    random.init_from_bin(bytes(new_key))
    self.data_size_list0 = [int(random.next() % 2340 % 2040 % 1440)
                            for _ in range(random.next() % 24 + 12)]
    self.data_size_list0.sort()
    old_len = len(self.data_size_list0)
    self.check_and_patch_data_size(random)
    if old_len != len(self.data_size_list0): self.data_size_list0.sort()
auth_chain.auth_chain_f.init_data_size = chain_f_init_data_size

signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
with open(sys.argv[2], 'r') as f: config = json.load(f)
pool = ServerPool.get_instance()
pool.new_server(config['server_port'], config)
while True: time.sleep(60)
""", encoding="utf-8")
    server_log = (root / "server.log").open("wb")
    xray_log = (root / "xray.log").open("wb")
    server = subprocess.Popen([sys.executable, str(wrapper), str(python_dir), str(server_json), str(root / "openssl.cnf")], stdout=server_log, stderr=subprocess.STDOUT)
    client = None
    try:
        wait_tcp(ssr_port, server)
        client = subprocess.Popen([str(xray), "run", "-c", str(xray_json)], stdout=xray_log, stderr=subprocess.STDOUT)
        wait_tcp(inbound_port, client)
        exchange(inbound_port, f"{method}/{protocol}/{obfs}")
    except Exception as exc:
        server_log.flush(); xray_log.flush()
        server_tail = (root / "server.log").read_text(errors="replace")[-4000:]
        xray_tail = (root / "xray.log").read_text(errors="replace")[-4000:]
        raise RuntimeError(f"{method}/{protocol}/{obfs}: {exc}\nSERVER:\n{server_tail}\nXRAY:\n{xray_tail}") from exc
    finally:
        if client is not None: stop(client)
        stop(server)
        server_log.close(); xray_log.close()


def main():
    python_dir = pathlib.Path(os.environ.get("SSR_PYTHON_DIR", "/private/tmp/ShadowsocksRR")).resolve()
    xray = pathlib.Path(os.environ.get("XRAY_BINARY", "/private/tmp/xray-ssr-compat")).resolve()
    commit = subprocess.check_output(["git", "-C", str(python_dir), "rev-parse", "HEAD"], text=True).strip()
    if commit != PINNED_COMMIT:
        raise SystemExit(f"server commit {commit}, expected {PINNED_COMMIT}")
    if not xray.is_file():
        raise SystemExit(f"XRAY_BINARY does not exist: {xray}")
    echo_port = echo_servers()
    cases = [("none", protocol, obfs) for protocol in PROTOCOLS for obfs in OBFS]
    cases += [(method, "origin", "plain") for method in CIPHER_SAMPLES if method != "none"]
    case_filter = os.environ.get("SSR_INTEROP_FILTER", "")
    if case_filter:
        cases = [case for case in cases if case_filter in "/".join(case)]
    with tempfile.TemporaryDirectory(prefix="xray-ssr-interop-") as temp:
        temp_root = pathlib.Path(temp)
        (temp_root / "openssl.cnf").write_text("""openssl_conf = openssl_init
[openssl_init]
providers = providers
[providers]
default = default_sect
legacy = legacy_sect
[default_sect]
activate = 1
[legacy_sect]
activate = 1
""", encoding="utf-8")
        for index, case in enumerate(cases):
            case_root = temp_root / str(index); case_root.mkdir()
            (case_root / "openssl.cnf").write_text((temp_root / "openssl.cnf").read_text(), encoding="utf-8")
            run_case(case_root, xray, python_dir, echo_port, *case)
            print("PASS", "/".join(case), flush=True)
    print(f"INTEROP_COMPLETE {len(cases)} cases")


if __name__ == "__main__":
    main()
