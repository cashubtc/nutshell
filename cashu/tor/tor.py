import os
import pathlib
import platform
import socket
import subprocess
from loguru import logger
import time


class TorProxy:
    def __init__(self):
        self.base_path = pathlib.Path(__file__).parent.resolve()
        self.platform = platform.system()
        self.keep_alive = 60 * 60  # seconds
        self.tor_proc = None
        self.pid_file = os.path.join(self.base_path, "tor.pid")
        self.tor_pid = None
        logger.info(f"Tor running: {self.is_running()}")
        logger.info(
            f"Tor port open: {self.is_port_open()}",
        )
        logger.info(f"Tor binary path: {self.tor_path()}")
        logger.info(f"Tor config path: {self.tor_config_path()}")
        logger.info(f"Tor PID in tor.pid: {self.read_pid()}")
        logger.info(f"Tor PID running: {self.signal_pid(self.read_pid())}")
        self.run_daemon()

    def run_daemon(self):
        if self.is_port_open() and not self.is_running():
            raise Exception(
                "Another Tor instance seems to be already running on port 9050."
            )
        if self.is_running():
            logger.info("Tor proxy already running.")
            return

        self.tor_proc = subprocess.Popen(
            [f"{self.tor_path()}", "--defaults-torrc", f"{self.tor_config_path()}"],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        logger.info("Running tor daemon with pid {}".format(self.tor_proc.pid))
        with open(self.pid_file, "w", encoding="utf-8") as f:
            f.write(str(self.tor_proc.pid))

    def stop_daemon(self, pid=None):
        pid = pid or self.tor_proc.pid if self.tor_proc else None
        if self.tor_proc and pid:
            self.signal_pid(pid, 15)  # sigterm
            time.sleep(5)
            self.signal_pid(pid, 9)  # sigkill

            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)

    def tor_path(self):
        PATHS = {
            "Windows": os.path.join(self.base_path, "bundle", "win", "tor.exe"),
            "Linux": os.path.join(self.base_path, "bundle", "linux", "tor"),
            "Darwin": os.path.join(self.base_path, "bundle", "mac", "tor"),
        }
        # make sure that file has correct permissions
        try:
            logger.debug(f"Setting permissions of {PATHS[platform.system()]} to 755")
            os.chmod(PATHS[platform.system()], 755)
        except:
            raise Exception("error setting permissions for tor binary.")
        return PATHS[platform.system()]

    def tor_config_path(self):
        return os.path.join(self.base_path, "torrc")

    def is_port_open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = ("127.0.0.1", 9050)
        try:
            s.connect(location)
            s.close()
            return True
        except Exception as e:
            return False

    def is_running(self):
        return self.tor_proc is not None

    def read_pid(self):
        if not os.path.isfile(self.pid_file):
            return None
        with open(self.pid_file, "r") as f:
            pid = f.readlines()
        # check if pid is valid
        if len(pid) == 0 or not int(pid[0]) > 0:
            return None
        return pid[0]

    def signal_pid(self, pid, signal=0):
        """
        Checks whether a process with pid is running (signal 0 is not a kill signal!)
        or stops (signal 15) or kills it (signal 9).
        """
        if not pid:
            return False
        print(f"running {pid} with signal={signal}")
        if not int(pid) > 0:
            return False
        pid = int(pid)
        try:
            os.kill(pid, signal)
        except:
            return False
        else:
            return True


if __name__ == "__main__":
    tor = TorProxy()
    time.sleep(5)
    logger.info("Killing Tor")
    tor.stop_daemon()
