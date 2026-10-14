"""Bounded native SquashFS, gzip and ESP image adapters.

Targets are parsed as bytes and never executed. ESP addresses come from the
validated image headers; filesystem offsets come from checked superblocks.
"""
import functools
import gzip
import hashlib
import operator
import os
from pathlib import Path
import shutil
import struct
import tempfile
import time

from .model import error as model_error, finish, new_report
from .process import bounded_run


def error(report, engine, code, message, status="failed"):
    if status == "partial" and report["scan_status"] != "failed":
        report["scan_status"] = "partial"
    model_error(report, engine, code, message, status)


def is_esp_header(data):
    if len(data) < 8 or data[0] != 0xe9 or not 1 <= data[1] <= 16:
        return False
    entry = int.from_bytes(data[4:8], "little")
    return 0x40000000 <= entry < 0x40400000


def arduino_crc(data):
    """CRC-32/MPEG-2 used by ESP8266 Arduino eboot's add_crc trailer.

    Format reference: esp8266/Arduino 2.7.4 tools/elf2bin.py, add_crc().
    The size and CRC words at 0xff8/0xffc are zero during calculation.
    """
    table = []
    for value in range(256):
        crc = value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
        table.append(crc)
    crc = 0xffffffff
    for at, byte in enumerate(data):
        if 0xff8 <= at < 0x1000:
            byte = 0
        crc = ((crc << 8) ^ table[(crc >> 24)^byte]) & 0xffffffff
    return crc


def parse_esp(data, start=0, header_size=8):
    if not is_esp_header(data[start:]):
        raise ValueError("Invalid ESP header")
    if header_size == 24:
        if start+24 > len(data) or int.from_bytes(data[start+12:start+14], "little") not in {0, 2, 9}:
            raise ValueError("ESP32 chip is outside validated Xtensa domain")
    pos, checksum, segments = start+header_size, 0xef, []
    for index in range(data[start+1]):
        if pos+8 > len(data):
            raise ValueError("Truncated ESP segment header")
        address, size = struct.unpack_from("<II", data, pos)
        pos += 8
        if not size or pos+size > len(data) or not 0x3f000000 <= address < 0x40400000 or address+size > 0x40400000:
            raise ValueError("Invalid ESP segment address/length")
        if any(address < a+len(b) and a < address+size for a, _, b, _ in segments):
            raise ValueError("Overlapping ESP virtual segments")
        content = data[pos:pos+size]
        checksum = functools.reduce(operator.xor, content, checksum)
        executable = 0x40000000 <= address < 0x40400000
        segments.append((address, pos, content, 1 if executable else 2))
        pos += size
    checksum_at = pos | 15
    if checksum_at >= len(data) or data[checksum_at] != checksum:
        raise ValueError("ESP image checksum mismatch/truncation")
    if any(data[pos:checksum_at]):
        raise ValueError("Invalid ESP checksum padding")
    end = checksum_at+1
    if header_size == 24 and data[start+23] == 1:
        if data[end:end+32] != hashlib.sha256(data[start:end]).digest():
            raise ValueError("ESP32 appended image SHA256 mismatch")
        end += 32
    return segments, end


def squashfs_offsets(data):
    result, pos = [], 0
    while True:
        at = data.find(b"hsqs", pos)
        if at < 0:
            break
        pos = at+4
        if at+96 > len(data):
            continue
        block_size = int.from_bytes(data[at+12:at+16], "little")
        major = int.from_bytes(data[at+28:at+30], "little")
        used = int.from_bytes(data[at+40:at+48], "little")
        if major == 4 and block_size >= 4096 and not block_size & (block_size-1) and 96 <= used <= len(data)-at:
            result.append({"offset": at, "size": used, "description": "validated SquashFS v4 superblock"})
            pos = at+used
    return result


def remaining(options, budget):
    return max(.001, options.timeout-(time.monotonic()-budget.started))


def context(report, relative):
    root = report["artifact"].get("firmware_sha256", report["artifact"]["sha256"])
    parent = report["artifact"].get("firmware_relative_path")
    return {"sha256": root, "relative_path": parent+"!/"+relative if parent else relative, "chain": report["extraction_chain"]}


def limit(report, options, budget):
    if budget.files >= options.max_files or budget.bytes >= options.max_bytes or remaining(options, budget) <= .001:
        report["scan_status"] = "partial"
        error(report, "firmware", "resource_limit", "Firmware file/byte/time budget exhausted", "partial")
        return True
    return False


def scan_esp(path, report, options, budget, depth, data):
    from .function_signatures import scan_functions
    from .scanner import run_engine
    from .yara_engine import scan_yara
    report["artifact"].update(format="firmware/ESP", architecture="Xtensa", endianness="little",
        firmware_sha256=report["artifact"].get("firmware_sha256", report["artifact"]["sha256"]))
    report["versions"]["firmware_adapter"] = {"name": "native-esp-e9", "binwalk_required": False,
        "arduino_format_reference": "https://github.com/esp8266/Arduino/blob/2.7.4/tools/elf2bin.py"}
    report["coverage_notes"].append("ESP8266 E9 and selected ESP32 Xtensa headers/segments/checksums are parsed. completed refers to recorded static channels; encrypted flash, RISC-V chips, secure-boot signatures and unknown Xtensa crypto implementations remain outside coverage.")
    image_start, images = 0, []
    while image_start < len(data):
        try:
            segments, end = parse_esp(data, image_start)
            header_size = 8
        except ValueError as first:
            try:
                segments, end = parse_esp(data, image_start, 24)
                header_size = 24
            except ValueError as second:
                report["scan_status"] = "failed" if not images else "partial"
                error(report, "firmware", "invalid_esp_image", f"Image at {image_start}: {first}; {second}", report["scan_status"])
                return
        images.append((image_start, segments, end, header_size))
        next_start = (end+4095) & ~4095
        if next_start < len(data) and is_esp_header(data[next_start:]):
            gap_end = next_start
            if image_start == 0 and next_start == 4096 and int.from_bytes(data[0xff8:0xffc], "little") == len(data):
                gap_end = 0xff8
                if int.from_bytes(data[0xffc:0x1000], "little") != arduino_crc(data):
                    error(report, "firmware", "arduino_crc_mismatch", "ESP8266 Arduino whole-image CRC mismatch", "partial")
                else:
                    report["artifact"]["arduino_crc"] = "verified"
            if any(b not in {0, 0xff, 0xaa} for b in data[end:gap_end]):
                error(report, "firmware", "unparsed_esp_gap", "Non-padding bytes between ESP images", "partial")
            image_start = next_start
        else:
            if any(b not in {0, 0xff, 0xaa} for b in data[end:]):
                error(report, "firmware", "unparsed_esp_trailer", "ESP trailer includes unparsed non-padding bytes", "partial")
            break
    with tempfile.TemporaryDirectory(prefix="qcs-esp-") as temp:
        for image_start, segments, end, header_size in images:
            if limit(report, options, budget):
                break
            relative = f"esp-image-{image_start:x}"
            ctx = context(report, relative)
            content = data[image_start:end]
            if len(content) > options.max_file_bytes or budget.bytes+len(content) > options.max_bytes:
                error(report, "firmware", "max_bytes", "ESP image exceeds child byte budget", "partial")
                break
            budget.files += 1
            budget.bytes += len(content)
            child = new_report(Path(relative), "executable")
            child["input_path"] = f"firmware:{ctx['sha256']}/{ctx['relative_path']}"
            child["artifact"].update(format="ESP/Xtensa", architecture="Xtensa", machine="EM_XTENSA", endianness="little", bits=32,
                sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content), symbol_state="unavailable",
                firmware_sha256=ctx["sha256"], container_sha256=report["artifact"]["sha256"],
                firmware_relative_path=ctx["relative_path"], image_offset=image_start)
            chain = {"engine": "native-esp", "input_sha256": report["artifact"]["sha256"], "offset": image_start,
                     "end": end, "header_size": header_size, "checksum": "verified", "depth": depth,
                     "segments": [{"address": a, "offset": off, "size": len(b), "executable": bool(flags & 1)} for a, off, b, flags in segments]}
            report["extraction_chain"].append(chain)
            child["extraction_chain"] = ctx["chain"]+[chain] if not ctx["chain"] or ctx["chain"][-1] != chain else list(ctx["chain"])
            child["engine_status"]["symbol"] = {"status": "disabled", "reason": "ESP image has no ELF/PE symbol tables"}
            # Match constants over the complete image, including data segments.
            # Function witnesses are restricted to executable address regions.
            image = Path(temp)/"image.bin"
            image.write_bytes(content)
            run_engine(child, "yara", lambda: scan_yara(image, child, options.rules, remaining(options, budget)))
            regions = [(a, off-image_start, b, flags) for a, off, b, flags in segments]
            run_engine(child, "function_signature", lambda: scan_functions(image, child, remaining(options, budget), regions=regions, architectures=["xtensa"]))
            from .guomi import scan_binary
            run_engine(child,'guomi',lambda: scan_binary(image,child,remaining(options,budget),regions=regions,architectures=['xtensa']))
            child["coverage_notes"].append("ESP executable ranges can contain readonly pools; format parsing and checksum verification do not prove complete Xtensa algorithm recognition.")
            report["components"].append(finish(child))
    report["engine_status"].setdefault("firmware", {"status": "completed", "adapter": "native-esp", "images": len(images)})


def text_component(path):
    raw = path.read_bytes()
    if not raw:
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ord(c) >= 32 or c in "\t\r\n\f" for c in text)


def scan_squashfs(path, report, options, budget, depth, hits):
    from .scanner import detect_kind, scan
    if not shutil.which("unsquashfs"):
        raise ModuleNotFoundError("unsquashfs missing; install squashfs-tools")
    report["artifact"].update(format="firmware/SquashFS", firmware_sha256=report["artifact"].get("firmware_sha256", report["artifact"]["sha256"]))
    report["versions"]["firmware_adapter"] = {"name": "native-squashfs-v4", "binwalk_required": False}
    report["extraction_chain"].append({"engine": "native-squashfs", "input_sha256": report["artifact"]["sha256"], "signatures": hits, "depth": depth})
    report["coverage_notes"].append("Native extraction covers validated SquashFS v4 filesystems; kernel/bootloader areas outside these filesystems are not analyzed by this adapter. Shell/config/HTML files are lexical text only. Symlinks are inventoried without following host paths.")
    with tempfile.TemporaryDirectory(prefix="qcs-firmware-") as temp:
        output = Path(temp)
        for index, hit in enumerate(hits):
            if limit(report, options, budget):
                break
            fsroot = output/f"filesystem-{index}"
            result = bounded_run(["unsquashfs", "-no-progress", "-processors", "1", "-d", str(fsroot), "-o", str(hit["offset"]), str(path)],
                timeout=remaining(options, budget), monitor=output, max_files=options.max_files-budget.files, max_bytes=options.max_bytes-budget.bytes)
            report.setdefault("extraction_log", "")
            report["extraction_log"] += result["output"].replace(str(output), "<extraction-root>")
            if result["limit"]:
                report["scan_status"] = "partial"
                error(report, "firmware", "extraction_limit", f"Extraction stopped at {result['limit']}", "partial")
            elif result["returncode"]:
                error(report, "firmware", "extraction_failed", f"unsquashfs exit {result['returncode']}; see extraction_log")
            if not fsroot.is_dir():
                continue
            for directory, dirs, files in os.walk(fsroot, followlinks=False):
                # Include directory symlinks in inventory but never descend.
                files += [name for name in dirs if (Path(directory)/name).is_symlink()]
                dirs[:] = sorted(name for name in dirs if not (Path(directory)/name).is_symlink())
                for name in sorted(files):
                    if limit(report, options, budget):
                        break
                    component = Path(directory)/name
                    inside = component.relative_to(fsroot).as_posix()
                    relative = inside if len(hits) == 1 else f"filesystem-{index}/"+inside
                    ctx = context(report, relative)
                    if component.is_symlink():
                        target = os.readlink(component)
                        if budget.bytes+len(os.fsencode(target)) > options.max_bytes:
                            error(report, "firmware", "max_bytes", "Symlink inventory exceeds byte budget", "partial")
                            break
                        budget.files += 1
                        budget.bytes += len(os.fsencode(target))
                        child = new_report(Path(relative), "symlink")
                        child["input_path"] = f"firmware:{ctx['sha256']}/{ctx['relative_path']}"
                        child["artifact"].update(format="filesystem/symlink", sha256=hashlib.sha256(os.fsencode(target)).hexdigest(),
                            sha256_method="symlink target bytes; content not followed", symlink_target=target)
                        child["engine_status"]["inventory"] = {"status": "completed"}
                        child["coverage_notes"].append("Symlink target inventoried only; canonical files are analyzed separately, runtime-generated targets remain outside this image.")
                        child["extraction_chain"] = list(ctx["chain"])
                        child = finish(child)
                    else:
                        selected = "auto"
                        if component.is_file() and component.stat().st_size <= min(options.max_file_bytes, options.max_bytes-budget.bytes) and detect_kind(component) == "unknown" and text_component(component):
                            selected = "text"
                        child = scan(component, selected, options, budget=budget, depth=depth+1, firmware_context=ctx)
                    child["artifact"].update(firmware_sha256=ctx["sha256"], container_sha256=report["artifact"]["sha256"], firmware_relative_path=ctx["relative_path"],
                        filesystem_relative_path=inside, extracted_relative_path=f"filesystem-{index}/"+inside, filesystem_image_offset=hit["offset"])
                    report["components"].append(child)
                if report["scan_status"] == "partial":
                    break
    if not report["components"] and not report["errors"]:
        report["scan_status"] = "unsupported"
        error(report, "firmware", "empty_filesystem", "No filesystem components extracted", "unsupported")
    report["engine_status"].setdefault("firmware", {"status": "completed", "adapter": "native-squashfs"})
    children = report["components"]
    report["component_coverage"] = {"total": len(children), "symlinks_inventoried": sum(c["input_kind"] == "symlink" for c in children),
        "regular_files_completed": sum(c["input_kind"] != "symlink" and c["scan_status"] == "completed" for c in children),
        "regular_files_uncompleted": sum(c["input_kind"] != "symlink" and c["scan_status"] != "completed" for c in children)}


def scan_gzip(path, report, options, budget, depth):
    from .scanner import scan
    report["artifact"]["format"] = "firmware/gzip"
    report["extraction_chain"].append({"engine": "native-gzip", "input_sha256": report["artifact"]["sha256"], "depth": depth})
    with tempfile.TemporaryDirectory(prefix="qcs-gzip-") as temp:
        output = Path(temp)/"payload.bin"
        size, cap = 0, min(options.max_file_bytes, options.max_bytes-budget.bytes)
        with gzip.open(path, "rb") as source, output.open("wb") as dest:
            while True:
                if remaining(options, budget) <= .001:
                    error(report, "firmware", "timeout", "gzip extraction deadline exhausted", "partial")
                    return
                chunk = source.read(min(65536, max(1, cap-size+1)))
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    error(report, "firmware", "extraction_limit", "gzip expanded byte limit exceeded", "partial")
                    return
                dest.write(chunk)
        child = scan(output, "auto", options, budget=budget, depth=depth+1, firmware_context=context(report, "gzip/payload"))
        child["artifact"].update(container_sha256=report["artifact"]["sha256"])
        report["components"].append(child)
    report["engine_status"]["firmware"] = {"status": "completed", "adapter": "native-gzip"}


def scan_native(path, report, options, budget, depth):
    """Return False only when no native format adapter applies."""
    data = path.read_bytes()
    if is_esp_header(data):
        scan_esp(path, report, options, budget, depth, data)
    elif data.startswith(b"\x1f\x8b\x08"):
        scan_gzip(path, report, options, budget, depth)
    elif hits := squashfs_offsets(data):
        scan_squashfs(path, report, options, budget, depth, hits)
    else:
        return False
    return True
