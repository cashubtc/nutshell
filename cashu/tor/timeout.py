#!/usr/bin/env python
import os
import subprocess
import sys
import time


def main():
    assert len(sys.argv) > 2, "Usage: timeout.py [seconds] [command...]"
    # cmd = " ".join(sys.argv[2:]) # for with shell=True
    cmd = sys.argv[2:]
    timeout = int(sys.argv[1])
    assert timeout > 0, "timeout (in seconds) must be a positive integer."
    start_time = time.time()

    pro = subprocess.Popen(cmd, shell=False)

    while time.time() < start_time + timeout + 1:
        time.sleep(1)
    pro.terminate()
    pro.wait()
    pro.kill()
    pro.wait()

    # we kill the child processes as well (tor.py and tor) just to be sure
    os.kill(pro.pid + 1, 15)
    os.kill(pro.pid + 1, 9)

    os.kill(pro.pid + 2, 15)
    os.kill(pro.pid + 2, 9)


if __name__ == "__main__":
    main()
