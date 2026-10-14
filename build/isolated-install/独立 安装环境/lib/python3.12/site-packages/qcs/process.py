"""Bound subprocess time and extraction resources, including child processes."""
import os
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

def tree_usage(root, max_files=None, max_bytes=None):
    count, size = 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
        for name in files:
            try:
                info = (Path(directory) / name).lstat()
                if stat.S_ISREG(info.st_mode):
                    count += 1
                    size += info.st_size
            except FileNotFoundError:
                continue
            if (max_files and count > max_files) or (max_bytes and size > max_bytes):
                return count, size
    return count, size

def bounded_run(command, *, timeout=60, cwd=None, monitor=None, max_files=None, max_bytes=None, env=None):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
            cwd=cwd, env=env, start_new_session=True)
        start, reason = time.monotonic(), None
        while process.poll() is None:
            if time.monotonic() - start > timeout:
                reason = "timeout"
            if monitor:
                count, size = tree_usage(monitor, max_files, max_bytes)
                if max_files and count > max_files:
                    reason = "max_files"
                if max_bytes and size > max_bytes:
                    reason = "max_bytes"
            if reason:
                os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.05)
        returncode = process.wait()
        if monitor and not reason:
            count, size = tree_usage(monitor, max_files, max_bytes)
            reason = "max_files" if max_files and count > max_files else "max_bytes" if max_bytes and size > max_bytes else None
        log.seek(0)
        output = log.read(512 * 1024).decode("utf-8", errors="replace")
        return {"returncode": returncode, "output": output, "limit": reason,
                "duration_seconds": round(time.monotonic() - start, 3)}
