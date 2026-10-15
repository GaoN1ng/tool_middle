"""Locate runtime resources in a checkout or an installed Linux wheel."""
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
WORKSPACE = PACKAGE.parents[1]
BUNDLED = PACKAGE / "resources"


def runtime_path(relative: str, bundled: str) -> Path:
    checkout = WORKSPACE / relative
    return checkout if checkout.exists() else BUNDLED / bundled


DEFAULT_RULES = runtime_path("third_party/crypto-detection/yararules/rules.yar", "yara/rules.yar")
DEFAULT_WINDRIVER = runtime_path("third_party/crypto-detector", "windriver")
