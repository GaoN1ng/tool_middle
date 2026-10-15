"""Locate packaged resources and keep checkout outputs under build/."""
import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
CHECKOUT = PACKAGE.parents[1] if PACKAGE.parent.name == "src" else None
WORKSPACE = CHECKOUT or Path.cwd().resolve()
BUILD = Path(os.environ.get("QCS_BUILD_DIR", str(WORKSPACE / "build"))).resolve()
BUNDLED = PACKAGE / "resources"


def resource_path(relative: str) -> Path:
    """Source checkout artifacts are shipped inside the qcs package in wheels."""
    if CHECKOUT is not None:
        staged = CHECKOUT / "build/runtime/qcs" / relative
        if staged.exists():
            return staged
    return PACKAGE / relative


def output_path(value) -> Path:
    """Resolve relative CLI outputs under build; reject external output paths."""
    path = Path(value)
    if not path.is_absolute():
        path = BUILD / (Path(*path.parts[1:]) if path.parts and path.parts[0] == "build" else path)
    path = path.resolve()
    if not path.is_relative_to(BUILD):
        raise ValueError(f"Output must be inside {BUILD}: {value}")
    return path


DEFAULT_RULES = BUNDLED / "yara/rules.yar"
DEFAULT_WINDRIVER = BUNDLED / "windriver"
