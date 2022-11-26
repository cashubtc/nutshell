import os
import pathlib
import platform
import socket
import subprocess
import sys
import time

from loguru import logger


class TorProxy:
    def __init__(self, timeout=False):
        self.base_path = pathlib.Path(__file__).parent.resolve()
        self.platform = platform.system()
        self.timeout = 60 * 60 if timeout else 0  # seconds
        self.tor_proc = None
        self.pid_file = os.path.join(self.base_path, "tor.pid")
        self.tor_pid = None
        self.startup_finished = True
        self.tor_running = self.is_running()

    @classmethod
    def check_platform(cls):
        if platform.system() == "Linux":
            if platform.machine() != "x86_64":
                logger.debug("Builtin Tor not supported on this platform.")
                return False
        return True

    def log_status(self):
        logger.debug(f"Tor binary path: {self.tor_path()}")
        logger.debug(f"Tor config path: {self.tor_config_path()}")
        logger.debug(f"Tor running: {self.tor_running}")
        logger.debug(
            f"Tor port open: {self.is_port_open()}",
        )
        logger.debug(f"Tor PID in tor.pid: {self.read_pid()}")
        logger.debug(f"Tor PID running: {self.signal_pid(self.read_pid())}")

    def run_daemon(self, verbose=False):
        if not self.check_platform() or self.tor_running:
            return
        self.log_status()
        logger.debug("Starting Tor")
        cmd = [f"{self.tor_path()}", "--defaults-torrc", f"{self.tor_config_path()}"]
        if self.timeout:
            logger.debug(f"Starting tor with timeout {self.timeout}s")
            cmd = [
                sys.executable,
                os.path.join(self.base_path, "timeout.py"),
                f"{self.timeout}",
            ] + cmd
        env = dict(os.environ)
        if platform.system() == "Linux":
            env["LD_LIBRARY_PATH"] = os.path.dirname(self.tor_path())
        elif platform.system() == "Darwin":
            env["DYLD_LIBRARY_PATH"] = os.path.dirname(self.tor_path())
        self.tor_proc = subprocess.Popen(
            cmd,
            env=env,
            shell=False,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        logger.debug("Running tor daemon with pid {}".format(self.tor_proc.pid))
        with open(self.pid_file, "w", encoding="utf-8") as f:
            f.write(str(self.tor_proc.pid))

        self.wait_until_startup(verbose=verbose)

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
            "Windows": os.path.join(self.base_path, "bundle", "win", "Tor", "tor.exe"),
            "Linux": os.path.join(self.base_path, "bundle", "linux", "tor"),
            "Darwin": os.path.join(self.base_path, "bundle", "mac", "tor"),
        }
        # make sure that file has correct permissions
        try:
            logger.debug(f"Setting permissions of {PATHS[platform.system()]} to 755")
            os.chmod(PATHS[platform.system()], 0o755)
        except:
            logger.debug("Exception: could not set permissions of Tor binary")
        return PATHS[platform.system()]

    def tor_config_path(self):
        return os.path.join(self.base_path, "torrc")

    def is_running(self):
        # another tor proxy is running
        if not self.is_port_open():
            return False
        # our tor proxy running from a previous session
        if self.signal_pid(self.read_pid()):
            return True
        # current attached process running
        return self.tor_proc and self.tor_proc.poll() is None

    def wait_until_startup(self, verbose=False):
        if not self.check_platform():
            return
        if self.is_port_open():
            return
        if self.tor_proc is None:
            raise Exception("Tor proxy not attached.")
        if not self.tor_proc.stdout:
            raise Exception("could not get tor stdout.")
        if verbose:
            print("Starting Tor...", end="", flush=True)
        for line in self.tor_proc.stdout:
            # print(line)
            if verbose:
                print(".", end="", flush=True)
            if "Bootstrapped 100%" in str(line):
                if verbose:
                    print("done", flush=True)
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
    tor = TorProxy(timeout=True)
    tor.run_daemon(verbose=True)
    # time.sleep(5)
    # logger.debug("Killing Tor")
    # tor.stop_daemon()
