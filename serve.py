#!/usr/bin/env python3
"""Static server for the afterglow pages, with caching turned off.

The PS4 browser keeps an application cache keyed on the manifest URL, and it
serves the cached HTML before it ever parses the page, so a manifest attribute
edit is invisible to it. The escape is to serve every page with no-store and
give the pages that matter no manifest at all -- then the browser has nothing
to pin and revalidation happens on every load.

    python serve.py 8001

Run it from this directory, or launch it with START-WINDOWS.bat (Windows) or
START-MAC-LINUX.sh, which do the same thing and keep the window open on error.

It prints the address to type on the console. That address is the reason this
replaces `python -m http.server`: reading it off a television is easy to get
wrong, so it is printed instead of guessed.
"""

import errno
import http.server
import os
import socket
import socketserver
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))

# Types the PS4 browser needs spelled out; the stdlib table is missing some.
EXTRA_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".appcache": "text/cache-manifest",
    ".bin": "application/octet-stream",
    ".wasm": "application/wasm",
    ".json": "application/json",
}

# Enough files to prove the folder is intact. If one is missing the page would
# load and then sit on "RAM: checking..." forever, which looks like a RAM fault
# and is not one.
REQUIRED = ("index.html", "jb.html", "jb15.html", "jb.js", "afterglow.js",
            "core.js", "mem.js", "int64.js", "ps4_offsets.js", "nova1402.bin")


def local_ipv4s():
    """Addresses another machine on the LAN could reach us on.

    The UDP connect sends nothing -- it only asks the routing table which local
    address would be used -- so this works with no internet access.
    """
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            found.append(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found:
                found.append(ip)
    except OSError:
        pass
    return [ip for ip in found
            if not ip.startswith("127.") and not ip.startswith("169.254.")]


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_POST(self):
        """Accept a run log. The console posts its whole log here so the
        values are exact instead of read off a photograph of a television.

        /dump?rva=<hex>&len=<dec> takes raw kernel bytes. A kernel image is
        the one thing this project cannot get any other way -- the PUP
        payload is AES encrypted and no 14.02 image exists anywhere -- so a
        working kernel read is the only source of the real machine code, and
        it has to land on a disk before the console reboots.
        """
        path = self.path.split("?")[0].rstrip("/")
        if path not in ("/log", "/log.txt", "/dump"):
            self.send_error(404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 16 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(n)

        if path == "/dump":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            rva = qs.get("rva", ["0"])[0]
            seg = qs.get("seg", ["x"])[0]
            ddir = os.path.join(ROOT, "dump")
            os.makedirs(ddir, exist_ok=True)
            try:
                tag = "%s_%s" % (seg, int(rva, 16) & 0xffffffff)
            except ValueError:
                tag = "%s_%s" % (seg, rva)
            dest = os.path.join(ddir, tag + ".bin")
            with open(dest, "wb") as fh:
                fh.write(body)
            sys.stderr.write("  dump  %s  %d bytes  -> %s\n" % (tag, len(body), dest))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        dest = os.path.join(ROOT, "leak-dump.txt")
        with open(dest, "wb") as fh:
            fh.write(body)
        sys.stderr.write("  log   %d bytes  -> leak-dump.txt\n" % len(body))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def handle_one_request(self):
        """Serve one request, but name the one failure that looks like a bug.

        This port speaks plain HTTP and has no certificate. If the browser asks
        for https:// it opens a TLS handshake instead, and the bytes on the wire
        start with 0x16 0x03 (handshake record, TLS version major 3) rather than
        a request line. The default handler tries to parse that as HTTP, replies
        with 400, and the browser reports a protocol error -- which reads like
        a broken server when it is actually a wrong URL scheme.

        `https://` cannot be made to work here even with a certificate: a
        private address has no publicly trusted certificate, and the console
        will not accept an unknown issuer. So detect the handshake and say so.
        """
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if self.raw_requestline[:2] == b"\x16\x03":
                sys.stderr.write(
                    "\n  ------------------------------------------------------------\n"
                    "  A TLS handshake arrived on this port.\n\n"
                    "  This server speaks plain HTTP and has no certificate, so\n"
                    "  it cannot answer an https:// request. The console reached\n"
                    "  this machine -- the address is right -- but the scheme is\n"
                    "  not.\n\n"
                    "  Use exactly:\n\n"
                    "      http://<this-pc-ip>:%d/index.html\n\n"
                    "  not https://. If the console added the s by itself, or\n"
                    "  you pasted a link starting with https, retype it by hand.\n"
                    "  ------------------------------------------------------------\n\n"
                    % self.server.server_address[1]
                )
                self.close_connection = True
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(501, "Unsupported method (%r)" % self.command)
                return
            getattr(self, mname)()
            self.wfile.flush()
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in EXTRA_TYPES:
            return EXTRA_TYPES[ext]
        return super().guess_type(path)

    def end_headers(self):
        # no-store beats no-cache: no-cache still stores and revalidates, and
        # this browser's revalidation is the part that has been lying.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s  %s\n" % (self.address_string(), fmt % args))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    # A double-clicked console shows the banner immediately, but a redirected
    # or piped run buffers it until exit -- which is the one moment it is no
    # longer useful. Line buffering makes both behave the same.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    port = 8001
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("  Port must be a number, e.g.  serve.py 8001")
            return 2

    os.chdir(ROOT)

    missing = [f for f in REQUIRED if not os.path.exists(os.path.join(ROOT, f))]
    if missing:
        print()
        print("  This folder is incomplete. Missing:")
        for f in missing:
            print("      " + f)
        print()
        print("  Extract the WHOLE zip before starting the server. Running it")
        print("  from inside the zip viewer leaves files behind.")
        print()
        return 1

    try:
        httpd = Server(("0.0.0.0", port), Handler)
    except OSError as e:
        if getattr(e, "errno", None) in (errno.EADDRINUSE, 10048):
            print()
            print("  Port %d is already in use." % port)
            print()
            print("  Either the server is already running -- look for another")
            print("  window titled 'PS4 14.02 test server' -- or something else")
            print("  has that port. To use a different one:")
            print()
            print("      START-WINDOWS.bat 8002")
            print("      (or:  python serve.py 8002)")
            print()
            print("  Remember to use the same number in the console's URL.")
            print()
            return 1
        raise

    ips = local_ipv4s()
    print()
    print("=" * 62)
    print("  PS4 14.02 test server is running")
    print("=" * 62)
    print()
    print("  On the PS4 browser, open:")
    print()
    if ips:
        for ip in ips:
            print("      http://%s:%d/index.html" % (ip, port))
        if len(ips) > 1:
            print()
            print("  More than one address is listed because this PC has more")
            print("  than one network connection. The right one is the 192.168.x.x")
            print("  or 10.x.x.x address on the network the PS4 is also on.")
    else:
        print("      http://<this-pc-ip>:%d/index.html" % port)
        print()
        print("  Could not work out this PC's LAN address. Run 'ipconfig'")
        print("  (Windows) or 'ip addr' (Linux/Mac) and use the IPv4 address.")
    print()
    print("  Then pick Nova and press DEPLOY.")
    print()
    print("  If Windows asks about the firewall, allow it on private networks.")
    print("  Leave this window open while the console is running.")
    print()
    print("  Logs and dumps the console sends back land in this folder:")
    print("      leak-dump.txt   the run log")
    print("      dump\\           raw kernel reads, if the run gets that far")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
