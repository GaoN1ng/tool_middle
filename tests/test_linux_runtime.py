from support import WORKSPACE
"""Linux launch, feature readiness and minimal-locale regressions."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qcs.cli import doctor
from qcs.scanner import Options


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux runtime checks")
class LinuxRuntimeTests(unittest.TestCase):
    def test_launcher_from_unrelated_directory_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix="qcs-linux-") as tmp:
            directory = Path(tmp) / "中文 空格"
            directory.mkdir()
            launcher = directory / "扫描工具"
            launcher.symlink_to(WORKSPACE / "qcs")
            source = directory / "输入 文件.c"
            source.write_text("void work(){ sm3_init(ctx); }\n", encoding="utf-8")
            result = subprocess.run([str(launcher), "scan", str(source), "--no-windriver"], cwd=directory,
                                    env=dict(os.environ, QCS_PYTHON=sys.executable), capture_output=True,
                                    text=True, encoding="utf-8", timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual({a["algorithm"] for a in report["algorithm_assets"]}, {"SM3"})
            self.assertEqual(report["input_path"], str(source))

    def test_explicit_broken_interpreter_does_not_fall_back(self):
        result = subprocess.run([str(WORKSPACE / "qcs"), "doctor"],
                                env=dict(os.environ, QCS_PYTHON="/nonexistent/qcs/python"),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("setup-linux.sh", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_launcher_rejects_unsupported_python(self):
        unsupported = shutil.which("python3.13") or shutil.which("python3.11")
        if not unsupported:
            self.skipTest("No unsupported Python installed for the negative check")
        result = subprocess.run([str(WORKSPACE / "qcs"), "doctor"],
                                env=dict(os.environ, QCS_PYTHON=unsupported),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Python 3.12", result.stderr)

    def test_missing_optional_tools_and_disabled_windriver(self):
        with patch("qcs.cli.shutil.which", return_value=None), \
             patch("qcs.firmware.binwalk_command", side_effect=ModuleNotFoundError("missing")), \
             patch("qcs.windriver.engines") as engines:
            report = doctor(Options(windriver=False, windriver_root=Path("/nonexistent/qcs/windriver")))
        engines.assert_not_called()
        self.assertTrue(report["ready"], report["checks"])
        self.assertTrue(report["capabilities"]["source"])
        self.assertTrue(report["capabilities"]["executable"])
        self.assertTrue(report["capabilities"]["firmware_esp_gzip"])
        self.assertFalse(report["capabilities"]["firmware_squashfs"])
        self.assertFalse(report["capabilities"]["squashfs_fixture_build"])

    def test_report_and_manifest_encoding_under_ascii_locale(self):
        # An ASCII pathname keeps this check focused on text encoding, even when
        # CPython's filesystem encoding was explicitly forced to ASCII.
        with tempfile.TemporaryDirectory(prefix="qcs-encoding-") as tmp:
            directory = Path(tmp)
            source = directory / "input.c"
            source.write_text("/* 中文说明 */\nvoid work(){ sm3_init(ctx); }\n", encoding="utf-8")
            output, csv_output = directory / "report.json", directory / "report.csv"
            result = subprocess.run([sys.executable, "-m", "qcs", "scan", str(source), "--no-windriver",
                                     "--output", str(output), "--csv", str(csv_output)],
                                    env=dict(os.environ, PYTHONPATH=str(WORKSPACE / "quantum-crypto-scanner"),
                                             LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0"),
                                    capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["scan_status"], "completed")
            self.assertIn("SM3", csv_output.read_text(encoding="utf-8"))
            code = "from qcs.cli import write_json; write_json({'text': '\\u4e2d\\u6587'}, None)"
            result = subprocess.run([sys.executable, "-c", code],
                                    env=dict(os.environ, PYTHONPATH=str(WORKSPACE / "quantum-crypto-scanner"),
                                             LC_ALL="C", PYTHONUTF8="1"), capture_output=True, timeout=10)
            self.assertEqual(json.loads(result.stdout.decode("utf-8")), {"text": "中文"})
