#!/usr/bin/env python
import os
import signal
import subprocess
import sys
import time


def main():
    assert len(sys.argv) > 2, "Usage: timeout.py [seconds] [command...]"
    cmd = " ".join(sys.argv[2:])
    timeout = int(sys.argv[1])
    start_time = time.time()
    assert timeout > 0, "timeout (in seconds) must be a positive integer."

    pro = subprocess.Popen(cmd, shell=True)

    while time.time() < start_time + timeout:
        time.sleep(1)
        # check if process is still running
        try:
            os.getpgid(pro.pid)
        except ProcessLookupError:
            break

    # terminate process
    try:
        os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
    except ProcessLookupError:
        return

    # kill process
    time.sleep(1.0)
    try:
        os.killpg(os.getpgid(pro.pid), signal.SIGKILL)
    except ProcessLookupError:
        return


if __name__ == "__main__":
    main()
