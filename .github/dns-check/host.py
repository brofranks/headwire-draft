"""Exercise a real kernel tunnel and split DNS on a disposable CI host."""
import collections
import contextlib
import ipaddress
import os
import platform
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

darwin = platform.system() == "Darwin"
listener = "10.91.82.53"
addrs = ["127.0.0.81", "127.0.0.82", "127.0.0.83"]
records = ["192.0.2.81", "192.0.2.82", "192.0.2.83"]
calls = collections.defaultdict(set)
binary = str(Path(sys.argv[1]).resolve())
zone = "dns-ci.test"
host = "static." + zone
split = "split." + zone


def cmd(*args):
    return subprocess.check_output(args, text=True).strip()


def until(check):
    deadline = time.monotonic() + 20
    while not check():
        if time.monotonic() >= deadline:
            raise TimeoutError(check)
        time.sleep(0.1)


def response(query, address, tcp):
    end = 12
    labels = []
    while query[end]:
        size = query[end]
        labels.append(query[end + 1:end + 1 + size].decode("ascii").lower())
        end += 1 + size
    end += 5
    name = ".".join(labels)
    question = query[12:end]
    answer = b""
    flags = 0x8183
    if name.endswith("." + zone) and int.from_bytes(query[end-4:end-2], "big") == 1:
        calls[(name, address)].add("tcp" if tcp else "udp")
        flags = 0x8180 if tcp else 0x8380
        if tcp:
            answer = struct.pack("!HHHIH4s", 0xc00c, 1, 1, 0, 4, socket.inet_aton(records[addrs.index(address)]))
    return query[:2] + struct.pack("!5H", flags, 1, bool(answer), 0, 0) + question + answer


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(response(data, self.server.server_address[0], False), self.client_address)


class TCP(socketserver.StreamRequestHandler):
    def handle(self):
        while frame := self.rfile.read(2):
            data = self.rfile.read(int.from_bytes(frame, "big"))
            reply = response(data, self.server.server_address[0], True)
            self.wfile.write(struct.pack("!H", len(reply)) + reply)


def expect(name, index):
    addresses = {r[4][0] for r in socket.getaddrinfo(name + ".", None, socket.AF_INET, socket.SOCK_STREAM)}
    assert addresses == {records[index]}, (name, addresses)
    assert calls[(name, addrs[index])] == {"udp", "tcp"}, (name, dict(calls))
    print(f"{name}: UDP truncation and TCP answer from {addrs[index]}", flush=True)


def ethernet_service():
    iface = re.search(r"interface: (\S+)", cmd("route", "-n", "get", "default"))[1]
    services = cmd("networksetup", "-listnetworkserviceorder")
    return re.search(r"\(\d+\) ([^\n]+)\n\(Hardware Port: [^\n]+, Device: " + re.escape(iface) + r"\)", services)[1]


def stop(process, log):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    result = process.wait(timeout=20)
    log.flush()
    if result:
        raise RuntimeError(Path(log.name).read_text())


with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as cleanup:
    tmp = Path(tmp)
    for address in addrs if darwin else addrs[-1:]:
        if darwin:
            cmd("ifconfig", "lo0", "alias", address, "netmask", "255.255.255.255")
            cleanup.callback(cmd, "ifconfig", "lo0", "-alias", address)
        for transport, handler in [(socketserver.UDPServer, UDP), (socketserver.ThreadingTCPServer, TCP)]:
            server = transport((address, 53), handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cleanup.callback(server.server_close)
            cleanup.callback(server.shutdown)
    if darwin:
        service = ethernet_service()
        old = cmd("networksetup", "-getdnsservers", service).splitlines()
        restore = ["Empty"] if old[0].startswith("There aren't any DNS Servers") else old
        cleanup.callback(cmd, "networksetup", "-setdnsservers", service, *restore)
        cmd("networksetup", "-setdnsservers", service, addrs[0])
        until(lambda: addrs[0] in Path("/etc/resolv.conf").read_text())
    private = cmd(binary, "genkey")
    conf = tmp / "test.conf"
    conf.touch(mode=0o600)
    conf.write_text(f"[Interface]\nPrivateKey = {private}\nAddress = 100.68.91.1/32\n"
                    f"[DNS]\nAddress = {listener}\nHost = {host} 192.0.2.44 2001:db8::44\nRoute = {split} {addrs[2]}\n")
    log = cleanup.enter_context((tmp / "daemon.log").open("w"))
    process = subprocess.Popen([binary, "run", str(conf)], stdout=log, stderr=log)
    cleanup.callback(stop, process, log)
    def published():
        if process.poll() is not None:
            raise RuntimeError((tmp / "daemon.log").read_text())
        state = cmd("scutil", "--dns") if darwin else cmd("resolvectl", "domain")
        return host in state and str(ipaddress.ip_address("192.0.2.44").reverse_pointer) in state
    try:
        until(published)
    except Exception:
        print((tmp / "daemon.log").read_text(), flush=True)
        print(cmd("scutil", "--dns") if darwin else cmd("resolvectl", "status"), flush=True)
        raise
    for address in ("192.0.2.44", "2001:db8::44"):
        actual = socket.getnameinfo((address, 0), socket.NI_NAMEREQD)[0].rstrip(".").lower()
        assert actual == host, (address, actual)
    print("System resolver returned both exact PTR records", flush=True)
    expect("before." + split, 2)
    if darwin:
        expect("before." + zone, 0)
        cmd("networksetup", "-setdnsservers", service, addrs[1])
        until(lambda: addrs[1] in Path("/etc/resolv.conf").read_text())
        expect("after." + zone, 1)
        expect("after." + split, 2)
    print("Host DNS checks passed", flush=True)
