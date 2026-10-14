"""Include runtime artifacts in wheels while keeping checkout JSON under build/."""
from pathlib import Path
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent


class RuntimeBuild(build_py):
    def run(self):
        super().run()
        runtime = ROOT / "build/runtime/qcs"
        if not (runtime / "rules/function_signatures.json").is_file():
            raise RuntimeError("Missing build/runtime/qcs. Restore runtime artifacts before building.")
        for source in runtime.rglob("*"):
            if source.is_file():
                target = Path(self.build_lib) / "qcs" / source.relative_to(runtime)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)

    def get_outputs(self, include_bytecode=1):
        return super().get_outputs(include_bytecode) + [str(Path(self.build_lib) / "qcs" / p.relative_to(ROOT / "build/runtime/qcs"))
            for p in (ROOT / "build/runtime/qcs").rglob("*") if p.is_file()]


if __name__ == "__main__":
    setup(cmdclass={"build_py": RuntimeBuild})
