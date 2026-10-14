#!/usr/bin/env bash
set -euo pipefail
qcs_root="$(dirname -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")")"
qcs_python=python3.12
qcs_wheelhouse=""
qcs_ml=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --python) qcs_python="$2"; shift 2 ;;
        --wheelhouse) qcs_wheelhouse="$(realpath "$2")"; shift 2 ;;
        --with-ml) qcs_ml=1; shift ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
cd "$qcs_root"
export QCS_BUILD_DIR="$qcs_root/build"
export PYTHONPYCACHEPREFIX="$qcs_root/build/cache/pycache"
export PIP_CACHE_DIR="$qcs_root/build/cache/pip"
export TMPDIR="$qcs_root/build/tmp"
mkdir -p "$TMPDIR" "$qcs_root/build/logs"
"$qcs_python" -c 'import sys; assert sys.version_info[:2] == (3,12), "Python 3.12 required"'
if [[ ! -x build/venv/bin/python ]]; then
    if ! "$qcs_python" -m venv build/venv; then
        "$qcs_python" -m venv --without-pip build/venv
    fi
fi
if ! build/venv/bin/python -m pip --version >/dev/null 2>&1; then
    qcs_bootstrap="$(find "$qcs_root/build/wheelhouse" -maxdepth 1 -name 'pip-*.whl' -print -quit)"
    if [[ -z "$qcs_bootstrap" ]]; then
        printf 'pip unavailable. Install python3.12-venv/ensurepip or restore build/wheelhouse/pip-*.whl.\n' >&2
        exit 2
    fi
    build/venv/bin/python -c 'import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); sys.argv[0]="pip"; runpy.run_module("pip",run_name="__main__")' \
        "$qcs_bootstrap" install --no-index "$qcs_bootstrap"
fi
qcs_pip_args=()
if [[ -n "$qcs_wheelhouse" ]]; then
    qcs_pip_args=(--no-index --find-links "$qcs_wheelhouse")
fi
build/venv/bin/python -m pip install "${qcs_pip_args[@]}" -r requirements.lock
if [[ $qcs_ml -eq 1 ]]; then
    build/venv/bin/python -m pip install "${qcs_pip_args[@]}" -r requirements-ml.lock
fi
build/venv/bin/python -m pip install "${qcs_pip_args[@]}" --no-build-isolation .
bin/qcs doctor --output reports/doctor.json
printf 'Installed. Run %s/bin/qcs scan INPUT --output reports/scan.json\n' "$qcs_root"
