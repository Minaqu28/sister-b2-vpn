# ip netns exec lan-b ./filexfer.py recv --listen 0.0.0.0:9000 --outdir transfer/endpoint-b
# ip netns exec lan-a ./filexfer.py send --to 192.168.2.10:9000 --file transfer/endpoint-a/data-uji.bin

import argparse
import hashlib
import os
import socket
import struct
import sys
import time

CHUNK = 64 * 1024


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.2f} {unit}"
        n /= 1024


def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"koneksi terputus saat membaca header ({len(buf)}/{n} byte)")
        buf.extend(chunk)
    return bytes(buf)


def do_recv(args):
    host, port = args.listen.rsplit(":", 1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(1)
    srv.settimeout(args.timeout)
    print(f"menunggu koneksi di {args.listen} …", flush=True)

    try:
        conn, peer = srv.accept()
    except socket.timeout:
        print("GAGAL: tidak ada koneksi masuk sebelum batas waktu", file=sys.stderr)
        return 1

    print(f"koneksi dari {peer[0]}:{peer[1]}", flush=True)
    conn.settimeout(args.timeout)

    try:
        name_len = struct.unpack("!H", recv_exact(conn, 2))[0]
        name = recv_exact(conn, name_len).decode("utf-8", errors="replace")
        size = struct.unpack("!Q", recv_exact(conn, 8))[0]
    except ConnectionError as err:
        print(f"GAGAL: {err}", file=sys.stderr)
        return 1

    name = os.path.basename(name) or "berkas-diterima.bin"
    os.makedirs(args.outdir, exist_ok=True)
    out_path = os.path.join(args.outdir, name)

    total = 0
    digest = hashlib.sha256()
    start = time.time()
    remaining = size
    with open(out_path, "wb") as f:
        while remaining > 0:
            block = conn.recv(min(CHUNK, remaining))
            if not block:
                print(f"GAGAL: koneksi terputus, baru menerima {total} dari {size} byte", file=sys.stderr)
                conn.close()
                srv.close()
                return 1
            f.write(block)
            digest.update(block)
            total += len(block)
            remaining -= len(block)
    elapsed = max(time.time() - start, 1e-6)
    conn.close()
    srv.close()

    print(f"nama file : {name}")
    print(f"diterima  : {total} byte ({human(total)})")
    print(f"durasi    : {elapsed:.2f} detik ({human(total / elapsed)}/detik)")
    print(f"sha256    : {digest.hexdigest()}")
    print(f"tersimpan : {out_path}")
    return 0


def do_send(args):
    name = os.path.basename(args.file)
    size = os.path.getsize(args.file)
    digest = sha256_file(args.file)

    host, port = args.to.rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)

    deadline = time.time() + args.timeout
    while True:
        try:
            s.connect((host, int(port)))
            break
        except (ConnectionRefusedError, socket.timeout, OSError) as err:
            if time.time() > deadline:
                print(f"GAGAL: tidak dapat terhubung ke {args.to}: {err}", file=sys.stderr)
                return 1
            time.sleep(0.3)
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(args.timeout)

    name_bytes = name.encode("utf-8")
    header = struct.pack("!H", len(name_bytes)) + name_bytes + struct.pack("!Q", size)

    start = time.time()
    s.sendall(header)
    sent = 0
    with open(args.file, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            s.sendall(block)
            sent += len(block)
    s.shutdown(socket.SHUT_WR)
    s.close()
    elapsed = max(time.time() - start, 1e-6)

    print(f"nama file : {name}")
    print(f"terkirim  : {sent} byte ({human(sent)})")
    print(f"durasi    : {elapsed:.2f} detik ({human(sent / elapsed)}/detik)")
    print(f"sha256    : {digest}")
    print(f"sumber    : {args.file}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="mode", required=True)

    r = sub.add_parser("recv")
    r.add_argument("--listen", default="0.0.0.0:9000")
    r.add_argument("--outdir", required=True, help="folder tujuan; berkas disimpan dengan nama aslinya")
    r.add_argument("--timeout", type=float, default=120.0)
    r.set_defaults(fn=do_recv)

    s = sub.add_parser("send")
    s.add_argument("--to", required=True)
    s.add_argument("--file", required=True)
    s.add_argument("--timeout", type=float, default=120.0)
    s.set_defaults(fn=do_send)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
