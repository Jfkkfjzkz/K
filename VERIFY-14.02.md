# 14.02 package — what is verified and how

Two separate things get called "the 14.02 offsets". They were checked against
different evidence and both now have a real basis.

## 1. The 89-field kpayload/hen table

Source of truth: upstream `Scene-Collective/ps4-hen@8c62f66` ("Add 14.02
support", 2026-11-12), which is a child of the `d077fb4` base.

    fields: upstream 89, ours 89
    IDENTICAL fields: 89 / 89
    DIFFERING fields: 0
    field order identical: yes

The AES pair is the row that had been wrong:

    AesCbcCfb128Encrypt_addr   ours 0x00341c10   upstream 0x00341c10
    AesCbcCfb128Decrypt_addr   ours 0x00341e40   upstream 0x00341e40

Twenty-four userland patch offsets do not move between 14.00 and 14.02 at all —
a point release does not rebuild those modules. The earlier build had applied a
per-field shift to them, which is what made 25 of 89 values wrong. That is
fixed; the table is now identical to upstream byte for byte.

Built artifacts:

    kpayload.bin   32,800 B   sha256 95cb02258b070b14d8aaa89daa5d3736da1cd90c6d92d9713388a685d45b3250
    nova1402.bin  500,672 B   sha256 4c2e47fff5d644352b98bc5417cac431f184a75510545f23b10f014aafd9e6f3

Both were rebuilt from source after the correction (`libPS4.a` compiled from the
SDK, not linked from a prebuilt blob) and re-checked: the build contains the
corrected AES pair and all ten folded `K1402_*` sites, and the stale pair is
absent.

## 2. The 15-row kernel patch table in afterglow.js

This is the table that was still open. It is now checked against both ends of
one 14.02 build:

    clean  1402k.elf          pre-patch kernel, SDK build, non-zero data
    post   14.02-dump.bin     kernel text off a console after the chain ran

Applying `PATCH_TABLE["14.02"]` to the clean image reproduces the console image
at all 15 rows:

| RVA | bytes written | clean byte | post byte | label |
|---|---|---|---|---|
| 0x00000acd | `eb` | `76` | `eb` | bcopy |
| 0x002bd79d | `eb` | `ba` | `eb` | bzero |
| 0x002bd7e1 | `eb` | `89` | `eb` | pagezero |
| 0x002bd85d | `eb` | `5b` | `eb` | memcpy |
| 0x002bd8a1 | `eb` | `e8` | `eb` | pagecopy |
| 0x002bda4d | `eb` | `00` | `eb` | copyin |
| 0x002bdefd | `eb` | `00` | `eb` | copyinstr |
| 0x002bdfcd | `eb` | `19` | `eb` | copystr |
| 0x001b7a43 | `eb04` | `48 8b` | `eb 04` | dlsym, first check |
| 0x001b7a53 | `eb04` | `00 00` | `eb 04` | dlsym, second check |
| 0x001b7a73 | `90e9` | `7d c0` | `90 e9` | dlsym, nop and jump |
| 0x001b7504 | `90e9` | `02 48` | `90 e9` | load_prx |
| 0x001b7ab8 | `90e93c01` | `83 fe 01 75` | `90 e9 3c 01` | dlsym, open to every caller |
| 0x00628684 | `eb00` | `03 02` | `eb 00` | self verification |
| 0x0062926f | `eb00` | `75 58` | `eb 00` | delayed panic on suspend |

**15 / 15 rows match.**

Across the whole 0xcfe880 text span only **237 bytes differ, in 42 runs**, and
every run is accounted for:

* the 15 rows above;
* seven writes the 14.02 bootstrap blob makes (`0x490`, `0x4b5`, `0x4b9`,
  `0x4c2`, `0xab4`, `0x1faeda`, `0x1faedd`) — each one is present verbatim in
  `BOOTSTRAP_TABLE["14.02"]`, which is how we know the dump came from a console
  running this chain and not from some other tool;
* three later hook trampolines (`0x3b3300`, `0x3b3830`, `0xb3a400`);
* four loader-filled absolute pointer tables at `0xb3a410..0xb3a4bf`;
* thirteen two-byte ASLR fixups in the first page, all consistent with a single
  load-base delta of 0x05a40000.

Nothing else in 13.6 MB moved.

### The "+0x300 shift" theory, and why it is dead

An earlier pass thought seven of the copy rows might be 0x300 too low, because
`memcpy_addr` in the kpayload table moves 0x2bd850 -> 0x2bdb50 between 14.00 and
14.02. Dumping those candidate addresses kills the idea: every one of them
(`0x2bda9d`, `0x2bdae1`, `0x2bdb5d`, `0x2bdba1`, `0x2bdd4d`, `0x2be1fd`,
`0x2be2cd`) holds the identical stack-clash prologue

    76 17 49 89 ea 49 83 c2 10 4c 39 d6 7d 0b 48 89

which is the boilerplate at the head of every one of these copy wrappers. It is
not a shifted copy of the bytes the table patches; it is a different
specialisation of the same wrapper. There is no uniform shift in this cluster,
and the table's RVAs are the ones a live 14.02 console actually carries.

### Residual risk, stated plainly

* Static analysis cannot prove that a `jmp` produced by overwriting the first
  byte of a multi-byte instruction is safe on every code path. For one row the
  arithmetic looks uncomfortable: `0x2bd85d` becomes `eb 41`, i.e. a jump to
  `0x2bd8a0`, which is the last byte of a `lea` under the most likely function
  alignment. The counter-evidence is that the console which carries these exact
  bytes was alive after the patch pass — it is the console the 13.6 MB dump came
  from. That is evidence, not proof.
* Nothing here has been executed on a 14.02 console in this session. The
  patch table, the bootstrap and the payload were validated against images and
  against each other, not by running them.

## 3. What each uploaded file was for

| file | used for |
|---|---|
| `1402k.elf` | the clean pre-patch kernel. This is what turned the 15-row table from "probably right" into a measured result, and it disproved the 0x300 theory. |
| `libkernel_web.sprx` | checked for the two `sceSblRcMgr*` debug-menu offsets. They are not confirmed (see below). |
| `libSceLibcInternal.sprx` | holds the ROP gadgets afterglow pivots through; the existing `GADGETS` rows were re-checked against it. |
| `libSceNKWebKit.sprx` | the WebKit module; not needed for the kernel table. |

The two `sceSblRcMgrIsAllowDebugMenuForSettings_patch` /
`sceSblRcMgrIsStoreMode_patch` values (`0x1D100`, `0x1D460`) are **not**
confirmed against `libkernel_web.sprx`: neither address lands on a function
entry. They are dead code in this build — `patch.c` calls `shellui_patch()`
behind `if (0)` — so they cannot cause a panic, but they should not be trusted
either.
