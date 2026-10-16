"""Regression + relocated PE fixtures + filesystem failure-path tests.

Run from this directory: python -m unittest -v
Real-binary tests are skipped if the repository's original artifacts are absent.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import sublime_patch as sp


class Code:
    def __init__(self, start):
        self.start = start
        self.b = bytearray()
        self.labels = {}
        self.fixups = []

    def add(self, b):
        self.b += b

    def rip(self, opcode, target, suffix=b''):
        self.add(opcode)
        end = self.start + len(self.b) + 4 + len(suffix)
        self.add(struct.pack('<i', target - end) + suffix)

    def jump(self, opcode, label, size=4):
        self.add(opcode)
        self.fixups.append((len(self.b), label, size))
        self.add(bytes(size))

    def label(self, name):
        self.labels[name] = self.start + len(self.b)

    def finish(self):
        for pos, label, size in self.fixups:
            end = self.start + pos + size
            self.b[pos:pos + size] = (self.labels[label] - end).to_bytes(size, 'little', signed=True)
        return bytes(self.b)


def fixture(code_base=0x1000, data_base=0x5000, near_purchase=False, short_update=False,
            duplicate_purchase=False, duplicate_update=False, machine=0x8664):
    """Small actual PE32+; code/data locations and branch widths are configurable."""
    pdata_base = max(code_base + 0x4000, data_base + 0x1000)
    strings = bytearray()
    addrs = {}
    for name, text in [
        ('body', b'Hello! Thanks for trying out Sublime Text.'),
        ('title', b'This is an unregistered copy'), ('button', b'Purchase'),
        ('config', b'update_check'), ('url', b'/updates/5/stable_update_check?version=9999'),
    ]:
        addrs[name] = data_base + len(strings)
        strings += text + b'\0'
    addrs['switch'] = data_base + 0x800
    addrs['counter'] = data_base + 0x810
    addrs['timestamp'] = data_base + 0x820
    addrs['queue'] = data_base + 0x830
    code = bytearray(b'\xcc' * 0x2000)
    funcs = []
    handler = code_base + 0x100
    stub = code_base + 0x1800

    def put(start, content):
        code[start - code_base:start - code_base + len(content)] = content
        funcs.append((start, start + len(content)))

    a = Code(handler)
    for op, key in [(b'\x48\x8d\x15', 'body'), (b'\x4c\x8d\x05', 'title'), (b'\x4c\x8d\x0d', 'button')]:
        a.rip(op, addrs[key])
    a.rip(b'\xe8', stub)
    a.add(b'\xc3')
    put(handler, a.finish())

    def purchase(start):
        a = Code(start)
        a.add(bytes.fromhex('56 48 83 ec 20 3c 01'))
        a.jump(b'\x0f\x85' if near_purchase else b'\x75', 'return', 4 if near_purchase else 1)
        a.rip(b'\x83\x25', addrs['counter'], b'\0')
        a.rip(b'\x48\x89\x35', addrs['timestamp'])
        a.rip(b'\x48\x8d\x0d', addrs['queue'])
        a.rip(b'\x48\x8d\x15', handler)
        a.add(bytes.fromhex('45 31 c0 48 83 c4 20 5e'))
        a.rip(b'\xe9', stub)
        a.label('return')
        a.add(bytes.fromhex('90 48 83 c4 20 5e c3'))
        put(start, a.finish())
    purchase(code_base + 0x200)
    if duplicate_purchase:
        purchase(code_base + 0x300)

    a = Code(code_base + 0x400)
    a.rip(b'\x48\x8d\x05', addrs['config'])
    a.rip(b'\x4c\x8d\x05', addrs['switch'])
    a.rip(b'\xe8', stub)
    a.rip(b'\xc6\x05', addrs['switch'], b'\1')
    a.add(b'\xc3')
    put(a.start, a.finish())

    def updater(start):
        a = Code(start)
        a.add(bytes.fromhex('53 48 83 ec 20'))
        a.rip(b'\x80\x3d', addrs['switch'], b'\1')
        a.jump(b'\x75' if short_update else b'\x0f\x85', 'return', 1 if short_update else 4)
        a.rip(b'\xe8', stub)
        a.add(bytes.fromhex('48 99 48 f7 f9 48 39 d0'))
        a.jump(b'\x75', 'return', 1)
        a.rip(b'\xe8', stub)
        a.label('return')
        a.add(bytes.fromhex('90 48 83 c4 20 5b c3'))
        put(start, a.finish())

    updater(code_base + 0x600)
    if duplicate_update:
        updater(code_base + 0x700)
    a = Code(code_base + 0x800)
    a.rip(b'\x48\x8d\x05', addrs['url'])
    a.rip(b'\xe8', code_base + 0x600)
    if duplicate_update:
        a.rip(b'\xe8', code_base + 0x700)
    a.add(b'\xc3')
    put(a.start, a.finish())
    put(stub, b'\xc3')
    pdata = b''.join(struct.pack('<III', begin, end, pdata_base + 0x800) for begin, end in sorted(funcs))
    pdata = pdata.ljust(0x800, b'\0') + bytes.fromhex('01 00 00 00')
    # DOS + COFF + PE32+ optional header + three section headers.
    header = bytearray(0x400)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3c, 0x80)
    header[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', header, 0x84, machine, 3, 0, 0, 0, 0xf0, 0x22)
    opt = 0x98
    struct.pack_into('<H', header, opt, 0x20b)
    struct.pack_into('<I', header, opt + 16, handler)
    struct.pack_into('<Q', header, opt + 24, 0x180000000)
    struct.pack_into('<II', header, opt + 32, 0x1000, 0x200)
    struct.pack_into('<II', header, opt + 56, pdata_base + 0x1000, 0x400)
    struct.pack_into('<H', header, opt + 68, 3)
    struct.pack_into('<I', header, opt + 108, 16)
    struct.pack_into('<II', header, opt + 112 + 3 * 8, pdata_base, len(funcs) * 12)
    sections = [
        (b'.text', code_base, 0x400, 0x2000, 0x60000020),
        (b'.data', data_base, 0x2400, 0x1000, 0xc0000040),
        (b'.pdata', pdata_base, 0x3400, 0x1000, 0x40000040),
    ]
    for n, (name, rva, raw, size, flags) in enumerate(sections):
        struct.pack_into('<8sIIIIIIHHI', header, opt + 0xf0 + n * 40,
                         name, size, rva, size, raw, 0, 0, 0, 0, flags)
    result = bytes(header) + bytes(code) + bytes(strings).ljust(0x1000, b'\0') + pdata.ljust(0x1000, b'\0')
    return result


class LocatorTests(unittest.TestCase):
    def test_relocated_addresses_and_branch_widths(self):
        for cb, db in [(0x1000, 0x5000), (0x9000, 0x2000)]:
            for near, short in [(False, False), (True, True)]:
                with self.subTest(code_base=cb, near_purchase=near, short_update=short):
                    data = fixture(cb, db, near_purchase=near, short_update=short)
                    _, patches, output = sp.analyze(data)
                    self.assertEqual([p.status for p in patches], ['needs_patch'] * 2)
                    self.assertEqual(len(output), len(data))
                    self.assertEqual(patches[0].rva, cb + 0x207)
                    self.assertEqual(len(bytes.fromhex(patches[0].after)), 6 if near else 2)
                    self.assertEqual(len(bytes.fromhex(patches[1].after)), 2 if short else 6)
                    _, again, same = sp.analyze(output)
                    self.assertEqual([p.status for p in again], ['already_patched'] * 2)
                    self.assertEqual(output, same)

    def test_missing_anchor(self):
        data = fixture().replace(b'Hello! Thanks', b'Hallo! Thanks')
        with self.assertRaises(sp.PatchError):
            sp.analyze(data)

    def test_ambiguous_purchase(self):
        with self.assertRaisesRegex(sp.PatchError, '唯一候选'):
            sp.analyze(fixture(duplicate_purchase=True))

    def test_ambiguous_update(self):
        with self.assertRaisesRegex(sp.PatchError, '唯一候选'):
            sp.analyze(fixture(duplicate_update=True))

    def test_invalid_return_and_stack_balance(self):
        image, patches, _ = sp.analyze(fixture())
        for patch_info in patches:
            data = bytearray(image.data)
            # Corrupt the stack release in each target epilogue.
            off = image.offset(patch_info.target_rva)
            self.assertEqual(data[off:off + 5], bytes.fromhex('90 48 83 c4 20'))
            data[off + 4] = 0x28
            with self.subTest(name=patch_info.name), self.assertRaises(sp.PatchError):
                sp.analyze(bytes(data))

    def test_invalid_pe_and_architecture(self):
        for data in (b'not PE', fixture(machine=0x14c)):
            with self.assertRaises(sp.PatchError):
                sp.analyze(data)

    def test_jump_range_validation(self):
        with self.assertRaises(sp.PatchError):
            sp.make_jump(0x1000, 0x2000, 2)
        with self.assertRaises(sp.PatchError):
            sp.make_jump(0, 1 << 40, 6)

    def test_unknown_branch_not_treated_as_patch(self):
        data = bytearray(fixture())
        _, patches, _ = sp.analyze(data)
        data[patches[0].file_offset] = 0x74  # opposite predicate
        with self.assertRaises(sp.PatchError):
            sp.analyze(bytes(data))


class FileFlowTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows process enumeration')
    def test_real_process_enumeration(self):
        self.assertIn(os.getpid(), sp.running_pids(Path(sys.executable)))
        with self.assertRaisesRegex(sp.PatchError, '仍在运行'):
            sp.require_stopped(Path(sys.executable))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / 'source.exe'
        self.data = fixture()
        self.exe.write_bytes(self.data)
        self.artifacts = self.root / 'reports'

    def apply(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return sp.apply_file(self.exe, self.artifacts, **kwargs)

    def test_dry_run_writes_nothing(self):
        before = sorted(self.root.rglob('*'))
        self.apply(dry_run=True)
        self.assertEqual(sorted(self.root.rglob('*')), before)
        self.assertEqual(self.exe.read_bytes(), self.data)

    def test_output_backup_restore_and_idempotency(self):
        output = self.root / 'output.exe'
        with patch.object(sp, 'running_pids', return_value=[]):
            manifest_path = self.apply(output=output)
            self.assertEqual(self.exe.read_bytes(), self.data)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(Path(manifest['backup']).read_bytes(), self.data)
            self.assertEqual(manifest['state'], 'applied')
            with self.assertRaises(sp.PatchError):
                self.apply(output=output)
            with contextlib.redirect_stdout(io.StringIO()):
                sp.restore(manifest_path)
            self.assertEqual(output.read_bytes(), self.data)
            self.assertEqual(json.loads(manifest_path.read_text())['state'], 'restored')

    @unittest.skipUnless(os.name == 'nt', 'Exclusive file writing requires Windows')
    def test_apply_restore_and_repeat_noop(self):
        with patch.object(sp, 'running_pids', return_value=[]):
            manifest_path = self.apply()
            before = sorted(self.root.rglob('*'))
            self.assertIsNone(self.apply())
            self.assertEqual(before, sorted(self.root.rglob('*')))
            with contextlib.redirect_stdout(io.StringIO()):
                sp.restore(manifest_path)
            self.assertEqual(self.exe.read_bytes(), self.data)

    def test_partial_patch_and_scope(self):
        _, patches, result = sp.analyze(self.data)
        partial = bytearray(self.data)
        p = patches[0]
        partial[p.file_offset:p.file_offset + len(bytes.fromhex(p.after))] = bytes.fromhex(p.after)
        _, located, output = sp.analyze(bytes(partial))
        self.assertEqual([x.status for x in located], ['already_patched', 'needs_patch'])
        self.assertEqual(output, result)

    def test_running_process_stops_before_backup(self):
        with patch.object(sp, 'running_pids', return_value=[123]):
            with self.assertRaisesRegex(sp.PatchError, '仍在运行'):
                self.apply()
        self.assertFalse(self.artifacts.exists())
        self.assertEqual(self.exe.read_bytes(), self.data)

    def test_backup_failure_does_not_modify_target(self):
        with patch.object(sp, 'running_pids', return_value=[]), patch.object(sp, 'write_new', side_effect=OSError('backup failed')):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.exe.read_bytes(), self.data)

    def test_source_changes_before_commit(self):
        calls = 0
        real_analyze = sp.analyze
        def racing_analyze(data):
            nonlocal calls
            calls += 1
            result = real_analyze(data)
            if calls == 2:
                self.exe.write_bytes(b'replaced by installer')
            return result
        with patch.object(sp, 'running_pids', return_value=[]), patch.object(sp, 'analyze', side_effect=racing_analyze):
            with self.assertRaisesRegex(sp.PatchError, '来源文件已变化'):
                self.apply()
        self.assertEqual(self.exe.read_bytes(), b'replaced by installer')
        self.assertEqual(json.loads(next(self.artifacts.rglob('manifest.json')).read_text())['state'], 'failed')

    def test_restore_rejects_new_installation(self):
        with patch.object(sp, 'running_pids', return_value=[]):
            manifest_path = self.apply(output=self.root / 'output.exe')
            (self.root / 'output.exe').write_bytes(b'new version')
            with self.assertRaises(sp.PatchError):
                sp.restore(manifest_path)
            self.assertEqual((self.root / 'output.exe').read_bytes(), b'new version')

    @unittest.skipUnless(os.name == 'nt', 'Exclusive file writing requires Windows')
    def test_failure_during_write_restores_original(self):
        real_fsync = sp.os.fsync
        calls = 0
        def failing_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError('simulated disk flush failure')
            return real_fsync(fd)
        _, _, output = sp.analyze(self.data)
        with patch.object(sp.os, 'fsync', side_effect=failing_fsync):
            with self.assertRaisesRegex(sp.PatchError, '已恢复并核验'):
                sp.replace_checked(self.exe, sp.digest(self.data), output)
        self.assertEqual(self.exe.read_bytes(), self.data)

    @unittest.skipUnless(os.name == 'nt', 'Windows exclusive file access')
    def test_locked_file_is_not_modified(self):
        _, _, output = sp.analyze(self.data)
        with self.exe.open('rb'), self.assertRaises(sp.PatchError):
            sp.replace_checked(self.exe, sp.digest(self.data), output)
        self.assertEqual(self.exe.read_bytes(), self.data)

    def test_output_write_failure_removes_only_own_partial_file(self):
        output = self.root / 'output.exe'
        real_fsync = sp.os.fsync
        def failure_on_output(fd):
            if output.exists():
                raise OSError('output fsync failed')
            return real_fsync(fd)
        with patch.object(sp, 'running_pids', return_value=[]), patch.object(sp.os, 'fsync', side_effect=failure_on_output):
            with self.assertRaises(OSError):
                self.apply(output=output)
        self.assertFalse(output.exists())
        self.assertEqual(self.exe.read_bytes(), self.data)


class RealBinaryTests(unittest.TestCase):
    def test_build_4200_states(self):
        artifact = Path(__file__).resolve().parent / 'artifacts' / 'sublime_4200'
        cases = [
            (artifact / 'sublime_text.original.exe', ['needs_patch', 'needs_patch']),
            (artifact / 'sublime_text.patched.exe', ['already_patched', 'needs_patch']),
            (artifact / 'update_fix_20261016' / 'after-update-fix.exe', ['already_patched'] * 2),
        ]
        if not all(path.exists() for path, _ in cases):
            self.skipTest('Build 4200 reference artifacts absent')
        for path, statuses in cases:
            with self.subTest(path=path.name):
                _, patches, output = sp.analyze(path.read_bytes())
                self.assertEqual([p.status for p in patches], statuses)
                self.assertEqual(sp.digest(output), '09EC1E939924892DCF93CF51115CA872275333B7CA772D17B5284C4E4F9B2996')


if __name__ == '__main__':
    unittest.main()
