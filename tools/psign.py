# -*- coding: utf-8 -*-
"""패치한 평문 ELF 를 다시 `~PSP` 실행 파일로 봉인한다 (제보 #7 후속).

이 파일만 **GPLv3** 다. sign_np(tpu / Hykem, GPLv3) 의 `eboot.c` 안
`sign_eboot()` 을 파이썬으로 옮긴 것이기 때문이다. 저장소의 나머지는 MIT.

    https://github.com/swarzesherz/sign_np

## 왜 필요한가

v1.8.0 은 복호한 평문 ELF 를 `EBOOT.BIN` 자리에 그대로 넣었다. PPSSPP 는
그래도 돌지만 **실기는 안 된다.** 실기 로더는 그 자리의 파일을 `~PSP` 로
보고 복호 경로를 태우는데, 평문 ELF 의 0xB0 자리(원래 `comp_size` 가
들어갈 곳)에는 ELF 본문 바이트가 있어 크기 검사에 걸린다.

    retsize = *(u32*)&buf[0xB0];
    if (size - 0x150 < retsize) return -4;     // 0xFFFFFFFC

제보된 오류 코드가 정확히 이 값이다(우리 파일의 0xB0 = 0x01CC4025 =
30,162,981 > 1,519,328). 그래서 답은 하나다 — **제대로 된 `~PSP` 로 다시
봉인해서 정상 경로로 들여보낸다.**

## 어떻게 통과하는가

`~PSP` 본문은 KIRK CMD1 블록이다. 앞 32바이트가 AES 키와 CMAC 키인데,
이 32바이트 자체는 KIRK 안의 마스터 키(`kirk1_key`)로 암호화돼 들어간다.
그 키는 실기에서 덤프돼 공개된 **진짜 하드웨어 키**라, 우리가 계산한 CMAC
두 개(헤더·본문)를 실기 KIRK 도 똑같이 검증하고 통과시킨다. 개인키가 필요한
ECDSA 경로는 `ecdsa_hash = 0` 이라 애초에 타지 않는다.

바깥 껍질은 태그(이 게임은 0xD9160BF0)로 정해지는 고정 키의 KIRK CMD4/7
스크램블이라 결정적으로 되돌릴 수 있다.

⚠ 원본과 **바이트 단위로 같은 파일이 나오지는 않는다.** 본문 AES 키가 다르니
암호문도 다르다. 되돌아오는 평문이 같을 뿐이다. 정품 서명의 복원이 아니므로
순정 펌웨어 구동은 보장하지 않는다(이 패치는 원래도 CFW·PPSSPP 전용이다).

## 쓰는 법

    python ../tools/psign.py eboot_kr.elf eboot_kr.bin

검산은 제3자 복호기로 한다. `pspdecrypt eboot_kr.bin` 이
**"with type 2"** 로 성공하고 결과가 입력 ELF 와 같아야 한다. type 2 는
CMAC 을 검증하는 경로다 — 본문을 한 바이트만 건드려도 type 6(무검증 폴백)
으로 떨어지고, SHA1 이나 CMAC 을 건드리면 아예 실패한다.
"""
import hashlib
import struct
import sys

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# KIRK 안의 마스터 키. 실기에서 덤프된 진짜 키다(kirk_engine, draan/proxima).
KIRK1 = bytes.fromhex('98C940975C1D10E87FE60EA3FD03A8BA')
# KIRK CMD4/7 이 code 0x5D 에 쓰는 고정 키.
KEY_5D = bytes.fromhex('115A5D20D53A8DD39CC5AF410F0F186F')
# sign_np 가 쓰는 고정 값. 아무 값이나 되지만 그대로 둔다(검산이 쉬워진다).
SEED_140 = bytes.fromhex('35FE4C9600B2F67EF583A6791FA0E886')
SEED_KIRK1 = bytes.fromhex(
    'CA0384B1D9634792CEC70123437268AC77EAECBA6DAA97DFFE91B93970998B3A')

# 이 게임(SN7Main)의 태그와 그 시드. 원본 EBOOT 헤더 0xD0 에서 읽은 값이다.
TAG = 0xD9160BF0
TAG_SEED = bytes([0x83, 0x83, 0xF1, 0x37, 0x53, 0xD0, 0xBE, 0xFC,
                  0x8D, 0xA7, 0x32, 0x52, 0x46, 0x0A, 0xC2, 0xC2])
CODE = 0x5D

# 이 게임의 원본 헤더에서 그대로 가져오는 값들. ELF 만 보고는 알 수 없다.
DEVKIT = 0x05050010
DECRYPT_MODE = 9                # UMD_GAME_EXEC

ZERO16 = bytes(16)


def _enc(key, data):
    return AES.new(key, AES.MODE_CBC, ZERO16).encrypt(data)


def _dec(key, data):
    return AES.new(key, AES.MODE_CBC, ZERO16).decrypt(data)


def _cmac(key, data):
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


def tag_key():
    """태그 시드를 KIRK CMD7 로 풀어 0x90바이트 키 뭉치를 만든다."""
    buf = bytearray(0x100)
    for i in range(9):
        buf[0x14 + i * 16:0x14 + i * 16 + 16] = TAG_SEED
        buf[0x14 + i * 16] = i
    n = ((0x90 + 0x14 + 15) // 16) * 16
    buf[0:n] = _dec(KEY_5D, bytes(buf[0x14:0x14 + n]))
    return bytes(buf[:0x90])


def psp_header(elf):
    """ELF 를 읽어 `~PSP` 헤더 0x150바이트를 세운다."""
    e_entry, = struct.unpack_from('<I', elf, 24)
    e_phoff, e_shoff = struct.unpack_from('<II', elf, 28)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
        struct.unpack_from('<HHHHH', elf, 42)
    shs = [struct.unpack_from('<10I', elf, e_shoff + i * e_shentsize)
           for i in range(e_shnum)]
    strtab = shs[e_shstrndx][4]

    def name(sh):
        o = strtab + sh[0]
        return elf[o:elf.index(b'\x00', o)].decode()

    modinfo = next((sh[4] for sh in shs
                    if name(sh) == '.rodata.sceModuleInfo'), None)
    phs = [struct.unpack_from('<8I', elf, e_phoff + i * e_phentsize)
           for i in range(e_phnum)]
    if modinfo is None:                     # 섹션이 없으면 p_paddr 이 답이다
        modinfo = phs[0][3]

    size = len(elf)
    h = bytearray(0x150)
    struct.pack_into('<I', h, 0x00, 0x5053507E)          # '~PSP'
    struct.pack_into('<HH', h, 0x04, 0, 0)               # 속성 / 압축 속성
    h[0x08] = h[0x09] = 1                                # 모듈 버전
    h[0x26] = 1                                          # 헤더 버전
    struct.pack_into('<I', h, 0x28, size)                # elf_size
    struct.pack_into('<I', h, 0x2C, ((size + 15) & ~15) + 0x150)   # psp_size
    struct.pack_into('<I', h, 0x30, e_entry)
    struct.pack_into('<I', h, 0x34, modinfo)
    struct.pack_into('<I', h, 0x78, DEVKIT)
    h[0x7C] = DECRYPT_MODE
    struct.pack_into('<H', h, 0x7E, 0)                   # overlap_size
    struct.pack_into('<I', h, 0xB0, size)                # comp_size
    struct.pack_into('<i', h, 0xB4, 0x80)

    modname = elf[modinfo + 4:modinfo + 4 + 28].split(b'\x00')[0]
    h[0x0A:0x0A + len(modname)] = modname

    n = 0
    for p_type, _off, p_vaddr, _paddr, p_filesz, p_memsz, _fl, p_align in phs:
        if p_type != 1:                                  # PT_LOAD 만
            continue
        struct.pack_into('<H', h, 0x3C + n * 2, p_align & 0xFFFF)
        struct.pack_into('<I', h, 0x44 + n * 4, p_vaddr)
        struct.pack_into('<i', h, 0x54 + n * 4, p_memsz)
        struct.pack_into('<i', h, 0x38, p_memsz - p_filesz)   # bss
        n += 1
    h[0x27] = n
    return bytes(h)


def sign(elf):
    """평문 ELF -> `~PSP` 바이트열."""
    if elf[:4] != b'\x7fELF':
        raise SystemExit('평문 ELF 가 아니다')
    size = len(elf)
    buf = bytearray(size + 4096)
    buf[0x150:0x150 + size] = elf
    head = psp_header(elf)

    # ---- KIRK CMD1 블록을 0x40 자리에 세운다 ----
    k = 0x40
    buf[k:k + 32] = SEED_KIRK1                        # AES 키 + CMAC 키
    struct.pack_into('<I', buf, k + 0x60, 1)          # mode = CMD1
    buf[k + 0x64] = 0                                 # ecdsa_hash 안 씀
    struct.pack_into('<I', buf, k + 0x70, size)
    struct.pack_into('<I', buf, k + 0x74, 0x80)
    buf[k + 0x90:k + 0x110] = head[:0x80]
    pad = (16 - size % 16) % 16
    for i in range(pad):                              # sign_np 와 같은 채움값
        buf[k + 0x110 + size + i] = 0xFF - i * 0x11
    body = size + pad

    aes_key, cmac_key = bytes(buf[k:k + 16]), bytes(buf[k + 16:k + 32])
    at = k + 0x90 + 0x80
    buf[at:at + body] = _enc(aes_key, bytes(buf[at:at + body]))
    buf[k + 0x20:k + 0x30] = _cmac(cmac_key, bytes(buf[k + 0x60:k + 0x90]))
    buf[k + 0x30:k + 0x40] = _cmac(
        cmac_key, bytes(buf[k + 0x60:k + 0x90 + 0x80 + body]))
    buf[k:k + 32] = _enc(KIRK1, SEED_KIRK1)           # 키 32B 를 봉인

    # ---- 바깥 껍질(태그 스크램블 + SHA1) ----
    tk = tag_key()
    t = bytearray(0x150)
    for i in range(0x40):
        t[0x14 + i] = buf[0x40 + i] ^ tk[0x50 + i]
    struct.pack_into('<IIIII', t, 0, 4, 0, 0, CODE, 0x40)   # KIRK CMD4 헤더
    t[0x80:0xC0] = _enc(KEY_5D, bytes(t[0x14:0x54]))
    for i in range(0x40):
        t[0x80 + i] ^= tk[0x10 + i]
    t[0xD0:0x150] = head[:0x80]
    t[0xC0:0xD0] = head[0xB0:0xC0]
    t[0x00:0x70] = bytes(0x70)
    t[0x70:0x80] = SEED_140
    t[0x08:0x18] = tk[0:0x10]
    struct.pack_into('<II', t, 0, 0x14C, TAG)
    t[0:0x14] = hashlib.sha1(bytes(t[4:4 + 0x14C])).digest()
    t[0x5C:0x6C] = SEED_140
    t[0x6C:0x80] = t[0:0x14]
    struct.pack_into('<IIIII', t, 0x48, 4, 0, 0, CODE, 0x60)
    t[0x5C:0xBC] = _enc(KEY_5D, bytes(t[0x5C:0xBC]))
    t[0:0x5C] = bytes(0x5C)
    struct.pack_into('<I', t, 0, TAG)

    buf[0x000:0x080] = t[0xD0:0x150]
    buf[0x080:0x0B0] = t[0x80:0xB0]
    buf[0x0B0:0x0C0] = t[0xC0:0xD0]
    buf[0x0C0:0x0D0] = t[0xB0:0xC0]
    buf[0x0D0:0x12C] = t[0x00:0x5C]
    buf[0x12C:0x140] = t[0x6C:0x80]
    buf[0x140:0x150] = t[0x5C:0x6C]
    return bytes(buf[:((size + 15) & ~15) + 0x150])


if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    out = sign(open(src, 'rb').read())
    open(dst, 'wb').write(out)
    print(f'{src} -> {dst}  {len(out):,}B  {out[:4]!r}')
