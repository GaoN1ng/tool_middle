"""Historical logical fixture paths are staged entirely inside this submission."""
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1] / "build/testing/workspace"
