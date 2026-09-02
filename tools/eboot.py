# -*- coding: utf-8 -*-
"""낭독 듣기 목록을 한글로 — **실행 파일 안의 표**를 고친다 (제보 #7).

낭독 듣기 화면의 장 목록은 스크립트도 아카이브도 읽지 않는다. 실행 파일
`EBOOT.BIN` 안에 하드코딩된 표 하나만 본다.

    표 @0xF0388   16바이트 × 86 레코드
    struct { u32 장라벨; u32 부제; u32 음성파일명; u32 재생시간 }

    장 개수   @0xF08E8 = [2,3,3,4,9,7,5,7,5,25,6,10]   (합 86)
    시작 인덱스 @0xF08F4 = [0,2,5,8,12,21,28,33,40,45,70,76]
    순서 = TU NF FW KM SI BH BM RM MH AA TA BJ

읽는 코드(vaddr 0xB948C)가 `표[시작인덱스[시나리오] + 장].라벨` 을 그대로
렌더러에 넘긴다. 그래서 `text/*.json` 을 아무리 고쳐도 이 화면은 안 바뀐다.

    lui v1,0xf ; addiu v1,v1,0x8a0   ; 시작 인덱스 배열
    lb  v1,0(v1) ; addu v1,v1,s2     ; + 장 번호
    sll v1,v1,4                      ; ×16 = 레코드 크기
    addiu v0,v0,0x334                ; 표 기준
    lw  a1,0(v0)                     ; 라벨 포인터 -> 렌더러

## 어디에 한글을 넣는가

원래 문자열 풀은 0x10D2CC~0x10DD9F(2,772B)인데, 그 안에 음성 파일명 86개가
1,291B 를 차지해 한글이 다 안 들어간다(4바이트 정렬 기준 151B 초과).

그래서 **풀은 손대지 않고** `.rodata.sceNid` 꼬리의 빈 자리를 쓴다.

    파일 0xE8DB4 ~ 0xE96FB = 2,376바이트, 전량 0x00

여기가 비어 있다는 근거는 넷이다. (1) `.lib.stub` 40칸을 전부 풀어 NID 표
끝을 계산하면 정확히 0xE8D60(vaddr)에서 끝난다. (2) 바이너리 전체의
R_MIPS_32 값과 HI16/LO16 주소 상수 중 이 구간으로 떨어지는 것이 0개다.
(3) 이 구간 안에 재배치 기록 위치가 0개라 로드 때 아무것도 안 써진다.
(4) gp(0x11E180) 상대 접근 사정권(0x116180~0x1261FF) 밖이다.

한글을 여기 깔고 표의 **라벨·부제 포인터 172칸만** 새 주소로 고친다. 음성
파일명 포인터 86칸과 풀 자체는 그대로 둔다 — 바뀌는 것이 가장 적은 방법이다.
`.rel.data` 의 R_MIPS_32 항목은 손댈 필요가 없다. 주소가 여전히 같은
세그먼트 안이라 재배치 규칙이 그대로 성립한다.

⚠ EBOOT.BIN 은 암호화돼 있고(`~PSP`) 재서명은 불가능하다. 그래서 pspdecrypt
로 푼 **평문 ELF 를 그대로 EBOOT.BIN 자리에 넣는다.** PSP CFW 와 PPSSPP 는
평문 ELF 를 그대로 읽는다 — PPSSPP 로 부팅·구동을 실제로 확인했다
("Relocatable module", 태그 ELF/SN7Main, 50초 동안 렌더·오디오 정상).

    python ../tools/eboot.py   ->  eboot_kr.elf
"""
import json
import os
import struct
import subprocess

import paths
import core

ADJ = 0x54                      # 파일오프셋 = 포인터값 + 0x54 (PT_LOAD off)
TABLE = 0xF0388
NREC = 86
CNT = 0xF08E8
START = 0xF08F4
FREE = (0xE8DB4, 0xE96FC)       # .rodata.sceNid 꼬리 — 전량 0, 참조 0
SCEN = ['TU', 'NF', 'FW', 'KM', 'SI', 'BH',
        'BM', 'RM', 'MH', 'AA', 'TA', 'BJ']
NUL = bytes([0])


def decrypt(iso_path=None, work='.'):
    """원본 ISO 의 EBOOT.BIN 을 pspdecrypt 로 풀어 평문 ELF 를 만든다."""
    exe = os.environ.get('TXL_PSPDECRYPT') or getattr(paths, 'PSPDECRYPT', '')
    if not exe or not os.path.exists(exe):
        raise SystemExit(
            'pspdecrypt 를 못 찾았다. 환경변수 TXL_PSPDECRYPT 에 실행 파일\n'
            '경로를 넣어라.  https://github.com/John-K/pspdecrypt')
    from isolib import Iso
    iso = Iso(iso_path) if iso_path else Iso()
    enc = os.path.join(work, 'eboot_enc.bin')
    open(enc, 'wb').write(iso.read_named('/PSP_GAME/SYSDIR/EBOOT.BIN'))
    subprocess.run([exe, enc], check=True, cwd=work)
    out = os.path.join(work, 'eboot_enc.elf')
    if not os.path.exists(out):
        raise SystemExit('복호 결과가 없다: ' + out)
    return open(out, 'rb').read()


def cstr(d, off):
    return d[off:d.find(NUL, off)]


def records(d):
    return [struct.unpack('<IIII', d[TABLE + k * 16:TABLE + k * 16 + 16])
            for k in range(NREC)]


def layout(d):
    """[(시나리오, 장, 레코드번호)] — 화면에 보이는 순서."""
    cnt, st = list(d[CNT:CNT + 12]), list(d[START:START + 12])
    return [(s, j + 1, st[i] + j)
            for i, s in enumerate(SCEN) for j in range(cnt[i])]


def patch_table(d, rows, align=4):
    """rows: [{'i':레코드, 'ko_label':…, 'ko_sub':…}] 를 반영한 새 바이트열."""
    d = bytearray(d)
    lo, hi = FREE
    if any(d[lo:hi]):
        raise SystemExit('빈 자리인 줄 알았던 곳에 값이 있다 — 중단')
    pool, addr = bytearray(), {}
    def put(t):
        b = core.encode(t) + NUL
        if b in addr:
            return addr[b]
        while len(pool) % align:
            pool.append(0)
        addr[b] = lo + len(pool) - ADJ
        pool.extend(b)
        return addr[b]
    by = {r['i']: r for r in rows}
    for k in range(NREC):
        r = by.get(k)
        if r is None:
            continue
        a, b, c, dur = struct.unpack('<IIII', d[TABLE + k * 16:TABLE + k * 16 + 16])
        d[TABLE + k * 16:TABLE + k * 16 + 8] = struct.pack(
            '<II', put(r['ko_label']), put(r['ko_sub']))
    if len(pool) > hi - lo:
        raise SystemExit(f'빈 자리가 모자란다: {len(pool)}B / {hi - lo}B')
    d[lo:lo + len(pool)] = pool
    return bytes(d), len(pool), hi - lo


def patch_loose(d, table):
    """풀 밖 낱개 문자열을 **슬롯 안에서** 제자리 교체한다.

    포인터를 안 건드리므로 슬롯(뒤따르는 NUL 채움까지)보다 길면 건너뛴다."""
    d = bytearray(d)
    done, skip = [], []
    want = {core.encode(k) if False else k.encode('cp932'): v
            for k, v in table.items()}
    for ja, ko in want.items():
        off = d.find(ja + NUL)
        if off < 0:
            skip.append((ko, '원문 없음'))
            continue
        e = off + len(ja)
        while e < len(d) and d[e] == 0:
            e += 1
        room, b = e - off, core.encode(ko)
        if len(b) + 1 > room:
            skip.append((ko, f'{len(b) + 1}B > 슬롯 {room}B'))
            continue
        d[off:off + room] = b + bytes(room - len(b))
        done.append((ko, off))
    return bytes(d), done, skip


if __name__ == '__main__':
    doc = json.load(open(os.path.join(paths.TEXT, 'eboot.json'),
                         encoding='utf-8'))
    src = os.environ.get('TXL_EBOOT_ELF') or 'eboot_enc.elf'
    d = open(src, 'rb').read() if os.path.exists(src) else decrypt()
    print(f'평문 ELF {len(d):,}B  {d[:4]!r}')
    d, used, room = patch_table(d, doc['reading'])
    print(f'표 172칸 재지정 / 한글 {used}B 를 빈 자리 {room}B 에 깔았다')
    d, done, skip = patch_loose(d, doc['extra'])
    print(f'낱개 문자열 {len(done)}건 교체' +
          (f' / 건너뜀 {skip}' if skip else ''))
    open('eboot_kr.elf', 'wb').write(d)
    print(f'-> eboot_kr.elf ({len(d):,}B)')
