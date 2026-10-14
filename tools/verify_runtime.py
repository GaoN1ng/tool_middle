#!/usr/bin/env python3
"""Smoke-check an installed wheel from an unrelated directory with spaces."""
import argparse
import json
import os
import sys
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.pycache_prefix = str(ROOT / "build/cache/pycache")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--python", type=Path, default=ROOT / "build/venv/bin/python")
    args = p.parse_args()
    # Preserve the venv pathname: resolving a venv Python symlink would lose
    # the venv context and silently use a different environment.
    python = args.python.absolute()
    cwd = ROOT / "build/isolated-install/运行 目录"
    cwd.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, QCS_BUILD_DIR=str(ROOT / "build"), PYTHONPYCACHEPREFIX=str(ROOT / "build/cache/pycache"),
               TMPDIR=str(ROOT / "build/tmp"), PYTHONUTF8="1")
    env.pop("PYTHONPATH", None)
    env.pop("QCS_PYTHON", None)
    catalog = json.loads((ROOT / "build/datasets/catalog.json").read_text(encoding="utf-8"))
    paths = {origin: ROOT / entry["path"] for entry in catalog["files"] for origin in entry["origins"]}
    checks = []

    def run(name, arguments, expected=None):
        result = subprocess.run([str(python), "-m", "qcs", *arguments], cwd=cwd, env=env,
                                capture_output=True, text=True, encoding="utf-8", timeout=180)
        try:
            report = json.loads(result.stdout)
        except ValueError:
            report = {}
        predicted = {a["algorithm"] for a in report.get("algorithm_assets", [])}
        passed = result.returncode == 0 and (expected is None or expected <= predicted)
        checks.append({"name": name, "passed": passed, "returncode": result.returncode,
                       "scan_status": report.get("scan_status"), "predicted": sorted(predicted),
                       "stderr": result.stderr, "errors": report.get("errors", [])})
        (ROOT / "build/checks" / (name + ".json")).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return report

    doctor = run("installed-doctor", ["doctor"])
    checks[-1]["passed"] = checks[-1]["passed"] and doctor.get("ready") is True
    for name, origin, algorithms in [
        ("installed-source", "samples/public-benchmark/sources/contiki-ng/os/lib/aes-128.c", {"AES"}),
        ("installed-elf", "quantum-crypto-scanner/fixtures/binary/rc4-holdout.so", {"RC4"}),
        ("installed-firmware", "samples/public-benchmark/firmware/tasmota-official-ota-current.bin", set()),
    ]:
        run(name, ["scan", str(paths[origin]), "--no-windriver"], algorithms)
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("pe_fixture", ROOT / "tools/legacy/pe_fixture.py")
    helper = module_from_spec(spec)
    spec.loader.exec_module(helper)
    pe = ROOT / "build/checks/structural-imports.exe"
    pe.write_bytes(helper.named_import_pe())
    run("installed-pe", ["scan", str(pe), "--no-windriver"], {"RSA", "ECDSA", "ECDH"})
    location = subprocess.run([str(python), "-c", "import qcs;print(qcs.__file__)"], cwd=cwd, env=env,
                              capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()
    passed_location = "site-packages/qcs" in location and str(ROOT / "src") not in location
    checks.append({"name": "installed-package-location", "passed": passed_location, "path": location})
    report = {"passed": all(c["passed"] for c in checks), "checks": checks,
              "policy": "No PYTHONPATH; installed wheel used from a directory with spaces; target programs never executed"}
    output = ROOT / "build/checks/installed-runtime.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
