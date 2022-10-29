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
        self.startup_finished = True
        self.tor_running = self.is_running()
        logger.debug(f"Tor running: {self.tor_running}")
        logger.debug(
            f"Tor port open: {self.is_port_open()}",
        )
        logger.debug(f"Tor binary path: {self.tor_path()}")
        logger.debug(f"Tor config path: {self.tor_config_path()}")
        logger.debug(f"Tor PID in tor.pid: {self.read_pid()}")
        logger.debug(f"Tor PID running: {self.signal_pid(self.read_pid())}")

        if not self.tor_running:
            logger.debug("Starting")
            self.run_daemon()

    def run_daemon(self):
        self.tor_proc = subprocess.Popen(
            [f"{self.tor_path()}", "--defaults-torrc", f"{self.tor_config_path()}"],
            shell=False,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        logger.debug("Running tor daemon with pid {}".format(self.tor_proc.pid))
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

    def is_running(self):
        # our tor proxy running from a previous session
        if self.signal_pid(self.read_pid()):
            logger.debug("Tor proxy already running.")
            return True
        # another tor proxy is running
        if self.is_port_open():
            logger.debug(
                "Another Tor instance seems to be already running on port 9050."
            )
            return True
        # current attached process running
        return self.tor_proc and self.tor_proc.poll() is None

    def wait_until_startup(self):
        if self.is_port_open():
            return
        if self.tor_proc is None:
            raise Exception("Tor proxy not attached.")
        if not self.tor_proc.stdout:
            raise Exception("could not get tor stdout.")
        for line in self.tor_proc.stdout:
            if "Bootstrapped 100%: Done" in str(line):
                break
        # tor is ready
        self.startup_finished = True
        return

    def is_port_open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = ("127.0.0.1", 9050)
        try:
            s.connect(location)
            s.close()
            return True
        except Exception as e:
            return False

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
    tor.wait_until_startup()
    # time.sleep(5)
    # logger.debug("Killing Tor")
    # tor.stop_daemon()
