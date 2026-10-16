#!/usr/bin/env python3
"""Locate and disable Sublime Text x64 purchase reminders / automatic updates.

No build-specific offsets or hash allowlists are used by the locator. Unknown
control-flow shapes fail closed. See README.md for the supported semantics.
"""
from __future__ import annotations

import argparse
import bisect
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
from datetime import datetime
from dataclasses import dataclass, asdict
import tempfile
import uuid

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP, X86_REG_RSP
except ImportError as exc:
    raise SystemExit("缺少依赖，请执行：python -m pip install -r requirements.txt\n" + str(exc))

DEFAULT_EXE = Path(r"D:\Program Files\Sublime Text\sublime_text.exe")
DEFAULT_ARTIFACTS = Path(__file__).resolve().parent / "artifacts" / "sublime_patch"


class PatchError(Exception):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def unique(values, description):
    values = list(values)
    if len(values) != 1:
        raise PatchError(f"{description}：要求唯一候选，实际 {len(values)} 个；未修改文件。")
    return values[0]


def immediate(ins):
    if len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
        return ins.operands[0].imm
    return None


def rip_target(ins):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.mem.disp
    return None


@dataclass(frozen=True)
class Function:
    start: int
    end: int


@dataclass
class Patch:
    name: str
    status: str
    rva: int
    file_offset: int
    before: str
    after: str
    target_rva: int
    evidence: dict


class Image:
    def __init__(self, data: bytes):
        self.data = data
        try:
            self.pe = pefile.PE(data=data, fast_load=True)
            if self.pe.FILE_HEADER.Machine != 0x8664 or self.pe.OPTIONAL_HEADER.Magic != 0x20B:
                raise PatchError("仅支持 Windows x64 PE32+，当前文件架构不支持。")
            self.pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
            ])
            self.functions = sorted({Function(e.struct.BeginAddress, e.struct.EndAddress)
                                     for e in getattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION', [])},
                                    key=lambda f: f.start)
        except (pefile.PEFormatError, ValueError, struct.error, AttributeError) as exc:
            raise PatchError(f"无效 PE 文件：{exc}") from exc
        if not self.functions:
            raise PatchError("缺少 x64 .pdata 函数边界；无法可靠定位。")
        self.starts = [f.start for f in self.functions]
        if any(f.end <= f.start for f in self.functions):
            raise PatchError(".pdata 函数范围无效。")
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.cache = {}
        self.raw_leas = {}
        # A fast prefilter only: every selected match is later checked against
        # instructions decoded FROM its .pdata function start.
        for section in self.pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            content = section.get_data()
            for m in re.finditer(rb"[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", content):
                i = m.start()
                if i + 7 > len(content):
                    continue
                rva = section.VirtualAddress + i
                target = rva + 7 + struct.unpack_from('<i', content, i + 3)[0]
                self.raw_leas.setdefault(target, []).append(rva)

    def offset(self, rva: int, length=1) -> int:
        for section in self.pe.sections:
            delta = rva - section.VirtualAddress
            if 0 <= delta and delta + length <= section.SizeOfRawData:
                off = section.PointerToRawData + delta
                if off + length <= len(self.data):
                    return off
        raise PatchError(f"RVA 0x{rva:X} 不在文件支持的节区范围内。")

    def rva_for_offset(self, offset):
        for section in self.pe.sections:
            delta = offset - section.PointerToRawData
            if 0 <= delta < section.SizeOfRawData:
                return section.VirtualAddress + delta
        raise PatchError("字符串不在映射节区内。")

    def containing(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and rva < self.functions[i].end:
            return self.functions[i]
        return None

    def instructions(self, fn):
        if fn.start not in self.cache:
            if fn.end - fn.start > 2 * 1024 * 1024:
                raise PatchError("函数过大，拒绝不受限反汇编。")
            off = self.offset(fn.start, fn.end - fn.start)
            insns = list(self.md.disasm(self.data[off:off + fn.end - fn.start], fn.start))
            if not insns or insns[-1].address + insns[-1].size != fn.end:
                raise PatchError(f"函数 0x{fn.start:X} 无法完整解码。")
            self.cache[fn.start] = insns
        return self.cache[fn.start]

    def at(self, rva):
        fn = self.containing(rva)
        if fn:
            return next((i for i in self.instructions(fn) if i.address == rva), None)
        return None

    def string_targets(self, text: bytes):
        values = []
        start = 0
        while True:
            off = self.data.find(text, start)
            if off < 0:
                return values
            start = off + len(text)
            try:
                values.append(self.rva_for_offset(off))
            except PatchError:
                pass

    def leas_to(self, targets):
        for target in targets:
            for rva in self.raw_leas.get(target, []):
                ins = self.at(rva)
                if ins and ins.mnemonic == 'lea' and rip_target(ins) == target:
                    yield ins

    def string_functions(self, text):
        return {self.containing(i.address) for i in self.leas_to(self.string_targets(text))}

    def version(self):
        for group in getattr(self.pe, 'FileInfo', []):
            for entry in group:
                for table in getattr(entry, 'StringTable', []):
                    value = table.entries.get(b'FileVersion')
                    if value:
                        return value.decode('utf-8', 'replace')
        return "unknown"


def return_epilogue(image, fn, target):
    """Require a straight stack-balanced epilogue, not merely a nearby RET."""
    insns = image.instructions(fn)
    tail = [i for i in insns if i.address >= target]
    if not tail or tail[0].address != target or tail[-1].mnemonic != 'ret':
        return False
    pushed, allocated = [], 0
    for i in insns:
        if i.mnemonic == 'push' and i.operands[0].type == X86_OP_REG:
            pushed.append(i.reg_name(i.operands[0].reg))
        elif (i.mnemonic == 'sub' and len(i.operands) == 2
              and i.operands[0].type == X86_OP_REG and i.operands[0].reg == X86_REG_RSP
              and i.operands[1].type == X86_OP_IMM):
            allocated += i.operands[1].imm
        elif i.mnemonic != 'nop':
            break
    popped, released = [], 0
    for i in tail:
        if i.mnemonic == 'nop':
            continue
        if i.mnemonic == 'ret':
            if i.operands:
                return False
        elif i.mnemonic == 'pop' and i.operands[0].type == X86_OP_REG:
            popped.append(i.reg_name(i.operands[0].reg))
        elif (i.mnemonic == 'add' and len(i.operands) == 2
              and i.operands[0].type == X86_OP_REG and i.operands[0].reg == X86_REG_RSP
              and i.operands[1].type == X86_OP_IMM):
            released += i.operands[1].imm
        else:
            return False
    return popped == list(reversed(pushed)) and released == allocated


def make_jump(rva, target, size):
    if size == 2:
        delta = target - (rva + 2)
        if not -128 <= delta <= 127:
            raise PatchError("短跳转目标超出范围。")
        return b'\xeb' + struct.pack('<b', delta)
    if size == 6:
        delta = target - (rva + 5)
        if not -(1 << 31) <= delta < (1 << 31):
            raise PatchError("近跳转目标超出范围。")
        return b'\xe9' + struct.pack('<i', delta) + b'\x90'
    raise PatchError("不支持该条件跳转长度。")


def branch_patch(image, name, fn, branch, evidence):
    target = immediate(branch)
    if target is None or not fn.start <= target < fn.end or not return_epilogue(image, fn, target):
        raise PatchError(f"{name}：分支目标不是已验证的正常返回路径。")
    if branch.mnemonic == 'jne' and branch.size in (2, 6):
        size, status = branch.size, 'needs_patch'
    elif branch.mnemonic == 'jmp' and branch.size == 2:
        size, status = 2, 'already_patched'
    elif branch.mnemonic == 'jmp' and branch.size == 5:
        following = image.at(branch.address + 5)
        if following is None or bytes(following.bytes) != b'\x90':
            raise PatchError(f"{name}：未知的已修改跳转形态。")
        size, status = 6, 'already_patched'
    else:
        raise PatchError(f"{name}：无法确认当前跳转形态。")
    off = image.offset(branch.address, size)
    before = image.data[off:off + size]
    after = make_jump(branch.address, target, size)
    if status == 'already_patched' and before != after:
        raise PatchError(f"{name}：跳转内容与预期不一致。")
    return Patch(name, status, branch.address, off, before.hex(' '), after.hex(' '), target, evidence)


def locate_purchase(image):
    anchors = [b'Hello! Thanks for trying out Sublime Text.',
               b'This is an unregistered copy\0', b'Purchase\0']
    handlers = set.intersection(*(image.string_functions(s) for s in anchors))
    handler = unique(handlers, '购买对话框构造函数')
    h_ins = image.instructions(handler)
    anchor_leas = [i for s in anchors for i in image.leas_to(image.string_targets(s))
                   if image.containing(i.address) == handler]
    if not any(i.mnemonic == 'call' and immediate(i) is not None
               and i.address > max(x.address for x in anchor_leas) for i in h_ins):
        raise PatchError('购买对话框：缺少加载文案后的构造调用。')
    candidates = []
    for callback in image.leas_to([handler.start]):
        fn = image.containing(callback.address)
        if fn == handler:
            continue
        insns = image.instructions(fn)
        cb_index = insns.index(callback)
        preceding = [i for i in insns[:cb_index] if i.group(CS_GRP_JUMP)]
        if not preceding:
            continue
        branch = preceding[-1]
        bi = insns.index(branch)
        compare = insns[bi - 1] if bi else None
        if not (compare and compare.mnemonic == 'cmp' and len(compare.operands) == 2
                and compare.operands[0].type == X86_OP_REG
                and compare.operands[1].type == X86_OP_IMM and compare.operands[1].imm == 1):
            continue
        # The fallthrough must set scheduling state and pass this exact callback
        # as a Windows x64 register argument to a distinct external scheduler.
        if callback.reg_name(callback.operands[0].reg) != 'rdx':
            continue
        target = immediate(branch)
        if target is None or target <= callback.address:
            continue
        fallthrough = [i for i in insns if branch.address + branch.size <= i.address < target]
        scheduler = [i for i in fallthrough if i.mnemonic in ('call', 'jmp')
                     and immediate(i) is not None and not fn.start <= immediate(i) < fn.end]
        state_writes = [i for i in fallthrough if i.mnemonic in ('mov', 'and')
                        and i.operands and i.operands[0].type == X86_OP_MEM
                        and i.operands[0].mem.base == X86_REG_RIP]
        if len(scheduler) != 1 or len(state_writes) < 2:
            continue
        if any(i.group(CS_GRP_JUMP) and i not in scheduler for i in fallthrough):
            continue
        if any(i.address > callback.address and i.address < scheduler[0].address
               and i.operands and i.operands[0].type == X86_OP_REG
               and i.reg_name(i.operands[0].reg) in ('rdx', 'edx') for i in fallthrough):
            continue
        candidates.append(branch_patch(image, 'purchase_reminder', fn, branch, {
            'handler_rva': handler.start, 'scheduler_function_rva': fn.start,
            'callback_reference_rva': callback.address, 'dispatch_rva': immediate(scheduler[0]),
            'anchors': [s.rstrip(b'\0').decode() for s in anchors],
        }))
    return unique(candidates, '购买提示调度分支')


def locate_update(image):
    config_functions = image.string_functions(b'update_check\0')
    # Recover the output pointer passed in R8 to the configuration getter.
    globals_to_readers = {}
    for fn in config_functions:
        insns = image.instructions(fn)
        for n, ins in enumerate(insns):
            if (ins.mnemonic != 'lea' or rip_target(ins) is None
                    or ins.reg_name(ins.operands[0].reg) != 'r8'):
                continue
            target = rip_target(ins)
            nearby = insns[max(0, n - 8):n]
            if not any(i.mnemonic == 'lea' and rip_target(i) in image.string_targets(b'update_check\0')
                       for i in nearby):
                continue
            if n + 1 >= len(insns) or insns[n + 1].mnemonic != 'call':
                continue
            if any(i.mnemonic == 'mov' and rip_target(i) == target and len(i.operands) == 2
                   and i.operands[0].type == X86_OP_MEM and i.operands[0].size == 1
                   and i.operands[1].type == X86_OP_IMM and i.operands[1].imm == 1 for i in insns):
                globals_to_readers.setdefault(target, []).append(fn.start)
    if not globals_to_readers:
        raise PatchError('自动更新：无法从配置读取及覆盖逻辑定位内部布尔开关。')
    url_anchors = sorted(set(m.group() for m in re.finditer(
        rb'/updates/[0-9]+/stable_update_check\?version=', image.data)))
    url_functions = set().union(*(image.string_functions(s) for s in url_anchors))
    if not url_functions:
        raise PatchError('自动更新：缺少受支持的 stable update URL 锚点。')
    candidates = {}
    for caller in url_functions:
        caller_insns = image.instructions(caller)
        for call in caller_insns:
            if call.mnemonic != 'call' or immediate(call) is None:
                continue
            fn = image.containing(immediate(call))
            if fn is None or fn.start != immediate(call):
                continue
            insns = image.instructions(fn)
            # Guard must precede ALL calls and appear immediately after prologue.
            for n, ins in enumerate(insns[:20]):
                if ins.mnemonic == 'call':
                    break
                if not (ins.mnemonic == 'cmp' and rip_target(ins) in globals_to_readers
                        and len(ins.operands) == 2 and ins.operands[0].type == X86_OP_MEM
                        and ins.operands[0].size == 1 and ins.operands[1].type == X86_OP_IMM
                        and ins.operands[1].imm == 1):
                    continue
                branch = insns[n + 1]
                target = immediate(branch)
                if target is None:
                    continue
                body = [i for i in insns if branch.address < i.address < target]
                # Time-dependent scheduling must precede a later task/request call.
                calls = [i for i in body if i.mnemonic == 'call' and immediate(i) is not None]
                if len(calls) < 2 or not any(i.mnemonic == 'idiv' for i in body):
                    continue
                if not any(i.mnemonic == 'cmp' and i.address > calls[0].address
                           for i in body):
                    continue
                if not any(i.group(CS_GRP_JUMP) and immediate(i) == target
                           for i in body):
                    continue
                patch = branch_patch(image, 'automatic_update', fn, branch, {
                    'function_rva': fn.start, 'config_switch_rva': rip_target(ins),
                    'config_reader_rvas': globals_to_readers[rip_target(ins)],
                    'url_caller_rvas': [caller.start],
                    'first_body_instruction_rva': branch.address + (6 if branch.size == 5 else branch.size),
                    'url_anchors': [s.decode('ascii') for s in url_anchors],
                    'first_body_call_rva': immediate(calls[0]),
                })
                if patch.rva in candidates:
                    candidates[patch.rva].evidence['url_caller_rvas'].append(caller.start)
                else:
                    candidates[patch.rva] = patch
    return unique(candidates.values(), '自动更新入口分支')


def analyze(data):
    image = Image(data)
    patches = [locate_purchase(image), locate_update(image)]
    output = bytearray(data)
    changed = set()
    for patch in patches:
        before, after = bytes.fromhex(patch.before), bytes.fromhex(patch.after)
        region = set(range(patch.file_offset, patch.file_offset + len(before)))
        if region & changed:
            raise PatchError('补丁范围重叠。')
        changed |= region
        if data[patch.file_offset:patch.file_offset + len(before)] != before:
            raise PatchError('构建期间原始字节发生变化。')
        output[patch.file_offset:patch.file_offset + len(after)] = after
        decoded = list(image.md.disasm(after, patch.rva))
        if not decoded or decoded[0].mnemonic != 'jmp' or immediate(decoded[0]) != patch.target_rva:
            raise PatchError('补丁后跳转解码校验失败。')
    output = bytes(output)
    if len(output) != len(data) or any(a != b and i not in changed for i, (a, b) in enumerate(zip(data, output))):
        raise PatchError('补丁长度或修改范围校验失败。')
    return image, patches, output


def running_pids(path):
    """Enumerate exact executable paths, fail closed on unexpected access errors."""
    if os.name != 'nt':
        raise PatchError('写入/恢复只支持 Windows；其他平台可使用 --dry-run。')
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    psapi.EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumProcesses.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    wanted = os.path.normcase(str(Path(path).resolve()))
    capacity = 4096
    while True:
        ids = (wintypes.DWORD * capacity)()
        used = wintypes.DWORD()
        if not psapi.EnumProcesses(ids, ctypes.sizeof(ids), ctypes.byref(used)):
            raise PatchError('无法枚举进程，停止写入。')
        if used.value < ctypes.sizeof(ids):
            break
        capacity *= 2
    found = []
    for pid in ids[:used.value // ctypes.sizeof(wintypes.DWORD)]:
        # Idle and System do not have a normal Win32 image path.
        if pid in (0, 4):
            continue
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            # Windows system/protected processes cannot be queried without
            # elevation. Exclusive file access below is the final lock check.
            if ctypes.get_last_error() in (5, 87):
                continue
            raise PatchError(f'无法检查进程 {pid}。')
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                if os.path.normcase(str(Path(buffer.value).resolve())) == wanted:
                    found.append(pid)
            # System/secure processes (e.g. Registry) may open successfully but
            # have no queryable Win32 path (ERROR_GEN_FAILURE). Processes can
            # also exit between EnumProcesses and this call.
            elif ctypes.get_last_error() not in (5, 6, 31, 87, 299):
                raise PatchError(f'无法读取进程 {pid} 的程序路径（Windows 错误 {ctypes.get_last_error()}）。')
        finally:
            kernel.CloseHandle(handle)
    return found


def require_stopped(path):
    pids = running_pids(path)
    if pids:
        raise PatchError(f'目标程序仍在运行（PID {pids}），请退出后重试；未终止进程。')


def write_new(path, data):
    with Path(path).open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_checked(path, expected, replacement):
    """Open without sharing to reject executing/locked files; keep lock on rollback."""
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(Path(path).resolve()), 0xC0000000, 0, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        err = ctypes.get_last_error()
        if err == 5:
            raise PatchError('目标文件无法写入，请在管理员终端重试，或确认程序已退出。')
        raise PatchError(f'无法独占目标文件（Windows 错误 {err}），可能正在运行或被占用。')
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, 'r+b') as f:
        current = f.read()
        if digest(current) != expected:
            raise PatchError('写入前哈希已变化，可能安装器替换了程序；未修改文件。')
        try:
            f.seek(0)
            if f.write(replacement) != len(replacement):
                raise OSError('short write')
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)
            if f.read() != replacement:
                raise OSError('post-write verification failed')
        except Exception as exc:
            try:
                f.seek(0)
                f.write(current)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
                f.seek(0)
                if f.read() != current:
                    raise OSError('rollback verification failed')
            except Exception as rollback:
                raise PatchError(f'写入失败，自动恢复也失败：{rollback}；请使用清单中的完整备份。') from exc
            raise PatchError(f'写入失败，已恢复并核验修改前内容：{exc}') from exc


def save_json(path, obj):
    text = json.dumps(obj, ensure_ascii=False, indent=2) + '\n'
    # Replace only our own manifest using a same-directory temporary file.
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.manifest-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def report_text(manifest):
    lines = ['# Sublime Text 补丁报告', '', f"状态：{manifest['state']}",
             f"版本：{manifest['version']}", f"来源：{manifest['source']}",
             f"目标：{manifest['destination']}", f"备份：{manifest['backup']}",
             f"修改前 SHA-256：{manifest['original_sha256']}",
             f"修改后 SHA-256：{manifest['patched_sha256']}", '',
             '| 功能 | 状态 | RVA | 文件偏移 | 原始字节 | 补丁字节 |',
             '|---|---|---|---|---|---|']
    for p in manifest['patches']:
        lines.append(f"| {p['name']} | {p['status']} | 0x{p['rva']:X} | 0x{p['file_offset']:X} | {p['before']} | {p['after']} |")
    lines += ['', '定位证据详见 manifest.json。只禁用自动更新；手动检查入口保留。',
              '修改签名程序会导致原 Authenticode 校验失效。新版结构不匹配时停止修改。', '']
    return '\n'.join(lines)


def apply_file(source, artifacts, output=None, dry_run=False):
    source = Path(source).resolve()
    original = source.read_bytes()
    image, patches, patched = analyze(original)
    print(f'版本 {image.version()}，SHA-256 {digest(original)}')
    for p in patches:
        print(f'{p.name}: {p.status}, RVA 0x{p.rva:X}, offset 0x{p.file_offset:X}: {p.before} -> {p.after}')
    if dry_run:
        print('预览完成，未创建文件或备份。')
        return None
    destination = Path(output).resolve() if output else source
    if output and destination == source:
        raise PatchError('--output 不能指向原始文件；原地应用请省略 --output。')
    if output and destination.exists():
        raise PatchError('--output 目标已存在，拒绝覆盖。')
    if patched == original and not output:
        print('两项均已修补，无需修改。')
        return None
    if output:
        require_stopped(destination)
    else:
        require_stopped(source)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    safe_version = re.sub(r'[^A-Za-z0-9_.-]', '_', image.version())[:80]
    run = Path(artifacts).resolve() / f'{safe_version}_{stamp}_{digest(original)[:12]}_{uuid.uuid4().hex[:8]}'
    run.mkdir(parents=True, exist_ok=False)
    backup = run / 'original.exe.bak'
    write_new(backup, original)
    if backup.read_bytes() != original:
        raise PatchError('备份核验失败，未写入目标。')
    manifest = dict(schema=1, state='prepared', version=image.version(), source=str(source),
                    destination=str(destination), backup=str(backup), created_at=datetime.now().astimezone().isoformat(),
                    original_sha256=digest(original), patched_sha256=digest(patched), file_size=len(original),
                    image_base=hex(image.pe.OPTIONAL_HEADER.ImageBase), patches=[asdict(p) for p in patches])
    manifest_path = run / 'manifest.json'
    save_json(manifest_path, manifest)
    (run / 'report.md').write_text(report_text(manifest), encoding='utf-8')
    output_created = False
    try:
        # Full semantic reanalysis of the candidate, including already-patched forms.
        _, checked, rebuilt = analyze(patched)
        if rebuilt != patched or any(p.status != 'already_patched' for p in checked):
            raise PatchError('候选文件重新定位失败。')
        if digest(source.read_bytes()) != digest(original):
            raise PatchError('分析后来源文件已变化，停止写入。')
        require_stopped(destination)
        if output:
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Claim the filename first; never delete or overwrite a racing
            # third-party file when recovering a failed output write.
            with destination.open('xb') as f:
                output_created = True
                f.write(patched)
                f.flush()
                os.fsync(f.fileno())
            if destination.read_bytes() != patched:
                raise PatchError('输出副本核验失败。')
        else:
            replace_checked(destination, digest(original), patched)
        manifest['state'] = 'applied'
    except Exception as exc:
        if output_created:
            try:
                destination.unlink()
            except OSError as cleanup:
                manifest['output_cleanup_error'] = str(cleanup)
        manifest['state'] = 'failed'
        manifest['error'] = str(exc)
        save_json(manifest_path, manifest)
        (run / 'report.md').write_text(report_text(manifest), encoding='utf-8')
        raise
    save_json(manifest_path, manifest)
    (run / 'report.md').write_text(report_text(manifest), encoding='utf-8')
    print(f'已完成并校验。SHA-256 {digest(patched)}\n清单：{manifest_path}\n备份：{backup}')
    return manifest_path


def restore(manifest_path):
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or manifest.get('state') not in ('prepared', 'applied'):
        raise PatchError('清单版本或状态不支持恢复。')
    target, backup = Path(manifest['destination']), Path(manifest['backup'])
    original = backup.read_bytes()
    if digest(original) != manifest['original_sha256'] or len(original) != manifest['file_size']:
        raise PatchError('备份哈希或大小不符，停止恢复。')
    require_stopped(target)
    replace_checked(target, manifest['patched_sha256'], original)
    manifest['state'] = 'restored'
    manifest['restored_at'] = datetime.now().astimezone().isoformat()
    save_json(path, manifest)
    (path.parent / 'report.md').write_text(report_text(manifest), encoding='utf-8')
    print(f'已恢复并校验：{target}\nSHA-256 {digest(original)}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=DEFAULT_EXE, help='Sublime Text x64 主程序路径')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--dry-run', action='store_true', help='只分析，不写任何文件')
    modes.add_argument('--output', type=Path, help='生成修补副本，不覆盖来源')
    modes.add_argument('--restore', type=Path, metavar='MANIFEST', help='按清单恢复完整备份')
    parser.add_argument('--artifacts-dir', type=Path, default=DEFAULT_ARTIFACTS, help='备份和报告根目录')
    args = parser.parse_args(argv)
    try:
        if args.restore:
            restore(args.restore)
        else:
            apply_file(args.exe, args.artifacts_dir, args.output, args.dry_run)
        return 0
    except PermissionError as exc:
        print(f'错误：权限不足，请使用管理员终端重试：{exc}', file=sys.stderr)
    except (PatchError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'错误：{exc}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
