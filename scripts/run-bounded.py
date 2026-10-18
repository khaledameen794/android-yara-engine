#!/usr/bin/env python3
"""Run finite cross-build work with a 15-minute wall and disk/inode safeguards."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
def problem():
    stats = os.statvfs(ROOT)
    if stats.f_bavail * stats.f_frsize < 2 * 1024 ** 3:
        return 'Less than 2 GiB free disk space'
    if stats.f_favail < 12000:
        return 'Less than 12000 free filesystem inodes'
    return None

def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: run-bounded.py COMMAND [ARGS...]')
    if reason := problem():
        raise SystemExit(reason)
    started = time.monotonic()
    process = subprocess.Popen(sys.argv[1:], cwd=ROOT, start_new_session=True)
    while process.poll() is None:
        reason = problem()
        if time.monotonic() - started > 900:
            reason = 'Build exceeded its 15-minute wall'
        if reason:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise SystemExit(reason)
        time.sleep(5)
    raise SystemExit(process.returncode)

if __name__ == '__main__':
    main()
