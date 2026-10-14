from support import WORKSPACE
import gzip
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from qcs.firmware_native import arduino_crc, parse_esp
from qcs.model import predictions
from qcs.scanner import Options, scan

BASE = WORKSPACE / "quantum-crypto-scanner/artifacts/coverage-fixes-20261012"


def esp_image(content=b"sensor data", address=0x40100000):
    body = struct.pack("<BBBBI", 0xe9, 1, 0, 0, address)
    body += struct.pack("<II", address, len(content))+content
    checksum = 0xef
    for byte in content:
        checksum ^= byte
    return body+bytes((-len(body)-1) % 16)+bytes([checksum])


class CoverageRepairTests(unittest.TestCase):
    def test_native_firmware_doctor_does_not_require_binwalk(self):
        from qcs.cli import doctor
        with patch('qcs.firmware.check_binwalk', side_effect=RuntimeError('Binwalk unavailable')):
            report = doctor(Options())
        self.assertTrue(report['ready'])
        self.assertTrue(next(c for c in report['checks'] if c['dependency'] == 'binwalk')['optional'])
    def test_pinned_custom_sources_are_recognized_after_rename(self):
        for relative, expected in [("contiki-ng/os/lib/aes-128.c", {"AES"}), ("openevse/src/crypto/sha256.c", {"SHA-256"})]:
            original = WORKSPACE/"samples/public-benchmark/sources"/relative
            with self.subTest(source=relative), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/"ordinary.c"
                path.write_bytes(original.read_bytes())
                report = scan(path, options=Options(windriver=False))
                self.assertEqual(predictions(report, "implementation_contains"), expected)
                path.write_bytes(original.read_bytes()+b"\n/* edited */\n")
                edited=scan(path,options=Options(windriver=False))
                self.assertFalse(any(f.get('implementation_verification')=='pinned_source_sha256' for f in edited['findings']))
                self.assertLessEqual(predictions(edited,'implementation_contains'),expected)
                if 'openevse' in relative:
                    self.assertEqual(predictions(edited,'implementation_contains'),expected)
                    self.assertTrue(any(f['engine']=='operation_source' for f in edited['findings']))

    def test_generic_custom_function_names_do_not_become_global_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"sha256.c"
            path.write_text('void sha256(void) {}\nvoid set_key(void) {}\nvoid encrypt(void) {}\nvoid f(void){sha256();set_key();encrypt();}\n')
            report = scan(path, options=Options(windriver=False))
            self.assertFalse(predictions(report, "implementation_contains"))
            self.assertFalse(predictions(report, "api_reference"))

    def test_rc4_requires_schedule_and_stream_witnesses(self):
        original = WORKSPACE/"quantum-crypto-scanner/fixtures/binary/rc4-holdout.so"
        report = scan(original)
        self.assertEqual(predictions(report, "implementation_contains"), {"RC4"})
        witness = next(f for f in report["findings"] if f["engine"] == "function_signature" and f["algorithm"] == "RC4")
        self.assertEqual(set(witness["matched_roles"]), {"key_schedule", "keystream"})
        with tempfile.TemporaryDirectory() as tmp:
            data = bytearray(original.read_bytes())
            stream = next(f for f in witness["matched_functions"] if f["role"] == "keystream")
            data[stream["offset"]] ^= 1
            path = Path(tmp)/"mutated.so"
            path.write_bytes(data)
            self.assertNotIn("RC4", predictions(scan(path), "implementation_contains"))

    def test_new_architectures_and_compiler_have_real_hidden_witnesses(self):
        for arch in ["thumb", "mipsel", "mips_be", "x86_64-gcc", "pe_x86_64"]:
            for module, expected in [("tiny-sha256", {"SHA-256"}), ("micro-ecdh", {"ECDH", "ECDSA"})]:
                with self.subTest(arch=arch, module=module):
                    suffix = ".dll" if arch == "pe_x86_64" else ".so"
                    path = BASE/"references"/arch/(module+"-O2-validation"+suffix)
                    report = scan(path)
                    self.assertEqual(report["scan_status"], "completed", report["errors"])
                    self.assertEqual(predictions(report, "implementation_contains"), expected)
                    self.assertTrue(any(f["engine"] == "function_signature" for f in report["findings"]))
                    if arch == "pe_x86_64":
                        import pefile
                        pe = pefile.PE(str(path))
                        try:
                            self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_EXPORT"))
                            self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_IMPORT"))
                            self.assertEqual(pe.FILE_HEADER.NumberOfSymbols, 0)
                            self.assertEqual(pe.FILE_HEADER.TimeDateStamp, 0)
                        finally:
                            pe.close()

    def test_pe_o0_pointer_relocations_preserve_hidden_ec_operations(self):
        report = scan(BASE/"references/pe_x86_64/micro-ecdh-O0-validation.dll")
        self.assertEqual(predictions(report, "implementation_contains"), {"ECDH", "ECDSA"})

    def test_xtensa_hidden_elf_and_esp_operational_witnesses(self):
        for opt in ["O0", "O2"]:
            for module, expected in [("tiny-sha256", {"SHA-256"}), ("micro-ecdh", {"ECDH", "ECDSA"}),
                                     ("negative-sha224-decoy", set()), ("negative-inert", set()), ("negative-loops", set())]:
                if module.startswith("negative-") and opt == "O0":
                    continue
                for suffix in [".elf", ".bin"]:
                    with self.subTest(opt=opt, module=module, suffix=suffix):
                        report = scan(BASE/"xtensa"/(module+"-"+opt+"-validation"+suffix))
                        self.assertEqual(report["scan_status"], "completed", report["errors"])
                        self.assertEqual(predictions(report, "implementation_contains"), expected)
                        if suffix == ".elf":
                            self.assertNotIn(".symtab", report["artifact"]["symbol_tables"])

    def test_declared_elf_zero_tail_is_lazy_bounded_and_never_executable(self):
        from qcs.function_signatures import ZeroFill, elf_load_regions, read_virtual
        segment = {'p_type': 'PT_LOAD', 'p_vaddr': 0x4000, 'p_offset': 0,
                   'p_filesz': 4, 'p_memsz': 1 << 30, 'p_flags': 7}
        class Segment(dict):
            def data(self):
                return b'data'
        elf = SimpleNamespace(elfclass=64, iter_segments=lambda: iter([Segment(segment)]))
        regions = elf_load_regions(elf)
        self.assertIsInstance(regions[1][2], ZeroFill)
        self.assertFalse(regions[1][3] & 1)
        self.assertEqual(read_virtual(regions, 0x4004, 4), bytes(4))
        self.assertIsNone(read_virtual(regions, 0x4000+(1 << 30)-2, 4))
        segment['p_memsz'] = 3
        with self.assertRaises(ValueError):
            elf_load_regions(elf)

    def test_xtensa_bss_pointer_constraint_rejects_changed_initial_data(self):
        from qcs.function_signatures import DATABASE, read_virtual
        path = BASE/'xtensa/micro-ecdh-O0-validation.bin'
        data = bytearray(path.read_bytes())
        report = scan(path)
        finding = next(f for f in report['components'][0]['findings'] if f['engine'] == 'function_signature' and f['algorithm'] == 'ECDH')
        function = next(f for f in finding['matched_functions'] if f['function'] == 'uECC_shared_secret')
        signature = next(s for s in json.loads(DATABASE.read_text())['signatures'] if s['id'] == function['signature_id'])
        segments, end = parse_esp(data)
        literal = next(l for l in signature['literals'] if l['kind'] == 'xtensa_l32r_pointer' and bytes.fromhex(l['bytes']) == bytes(4))
        pc = function['address']+literal['offset']
        instruction = read_virtual(segments, pc, 3)
        pool = ((pc+3)&~3)+(int.from_bytes(instruction[1:3], 'little')-65536)*4
        pointer = int.from_bytes(read_virtual(segments, pool, 4), 'little')
        target_offset = next(off+pointer-base for base, off, body, flags in segments if base <= pointer < base+len(body))
        data[target_offset] ^= 1
        data[end-1] ^= 1  # Keep the image checksum valid; change only initial data.
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp)/'changed.bin'
            changed.write_bytes(data)
            report = scan(changed)
        self.assertEqual(report['scan_status'], 'completed', report['errors'])
        self.assertNotIn('ECDH', predictions(report, 'implementation_contains'))

    def test_new_architecture_negative_controls_and_exec_mapped_rodata(self):
        for arch in ["thumb", "mipsel", "mips_be", "pe_x86_64", "x86_64-gcc"]:
            for name in ["sha224-decoy", "inert-tables", "generic-ec", "ordinary-loops", "code-as-data"]:
                with self.subTest(arch=arch, name=name):
                    suffix = ".dll" if arch == "pe_x86_64" else ".so"
                    report = scan(BASE/"negative-controls"/arch/(name+suffix))
                    self.assertEqual(report["scan_status"], "completed", report["errors"])
                    self.assertFalse(predictions(report, "implementation_contains"), report["findings"])

    def test_esp_parser_checks_lengths_checksum_and_segment_overlap(self):
        good = esp_image()
        segments, end = parse_esp(good)
        self.assertEqual(end, len(good))
        self.assertEqual(segments[0][0], 0x40100000)
        for bad in [good[:-1], good[:-1]+bytes([good[-1]^1]), good[:12]+struct.pack("<I", 0xffffffff)+good[16:]]:
            with self.subTest(bad=bad.hex()[:40]), self.assertRaises(ValueError):
                parse_esp(bad)

    def test_esp_native_scan_and_depth_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"sensor.bin"
            path.write_bytes(esp_image())
            report = scan(path)
            self.assertEqual(report["input_kind"], "firmware")
            self.assertEqual(report["scan_status"], "completed")
            self.assertEqual(report["components"][0]["artifact"]["architecture"], "Xtensa")
            self.assertEqual(report["components"][0]["extraction_chain"][-1]["checksum"], "verified")
            self.assertEqual(scan(path, options=Options(max_depth=0))["scan_status"], "partial")
            self.assertEqual(scan(path, options=Options(max_files=1))["scan_status"], "partial")
            path.write_bytes(path.read_bytes()[:-1]+b"\0")
            report = scan(path)
            self.assertEqual(report["scan_status"], "failed")
            self.assertFalse(report["components"])

    def test_real_tasmota_boot_and_application_crc(self):
        path = WORKSPACE/"samples/public-benchmark/firmware/tasmota-official-ota-current.bin"
        report = scan(path)
        self.assertEqual(report["scan_status"], "completed", report["errors"])
        self.assertEqual(report["artifact"]["arduino_crc"], "verified")
        self.assertEqual(len(report["components"]), 2)
        self.assertEqual(sum(len(c["extraction_chain"][-1]["segments"]) for c in report["components"]), 6)
        for child in report["components"]:
            self.assertEqual(child["artifact"]["container_sha256"], report["artifact"]["sha256"])
            self.assertNotIn("qcs-esp-", json.dumps(child))
        data = path.read_bytes()
        self.assertEqual(arduino_crc(data), int.from_bytes(data[0xffc:0x1000], "little"))

    def test_gzip_ota_limits_and_nested_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"image.bin.gz"
            path.write_bytes(gzip.compress(esp_image()))
            report = scan(path)
            self.assertEqual(report["scan_status"], "completed")
            image = report["components"][0]
            self.assertEqual(image["components"][0]["artifact"]["firmware_sha256"], report["artifact"]["sha256"])
            self.assertEqual(len(image["components"][0]["extraction_chain"]), 2)
            path.write_bytes(gzip.compress(bytes(1024*1024)))
            report = scan(path, options=Options(max_file_bytes=2048))
            self.assertEqual(report["scan_status"], "partial")
            self.assertTrue(any(e["code"] == "extraction_limit" for e in report["errors"]))

    @unittest.skipUnless(shutil.which("mksquashfs"), "requires squashfs-tools")
    def test_squashfs_offset_text_and_symlinks_without_binwalk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/"root"
            root.mkdir()
            (root/"boot-script").write_text('#!/bin/sh\necho RSA AES\n')
            (root/"escape").symlink_to("/etc/passwd")
            image = Path(tmp)/"image.squashfs"
            subprocess.run(["mksquashfs", str(root), str(image), "-noappend", "-processors", "1", "-no-xattrs"], check=True, capture_output=True)
            embedded = Path(tmp)/"embedded.img"
            embedded.write_bytes(bytes(512)+image.read_bytes())
            report = scan(embedded, "firmware", Options(binwalk="/nonexistent-binwalk"))
            self.assertEqual(report["scan_status"], "completed", report["errors"])
            self.assertEqual(len(report["components"]), 2)
            self.assertFalse(report["algorithm_assets"])
            self.assertEqual(report["component_coverage"]["symlinks_inventoried"], 1)
            for child in report["components"]:
                self.assertEqual(child["artifact"]["filesystem_image_offset"], 512)
            link = next(c for c in report["components"] if c["input_kind"] == "symlink")
            self.assertEqual(link["artifact"]["symlink_target"], "/etc/passwd")
            self.assertFalse(link["findings"])


if __name__ == "__main__":
    unittest.main()
