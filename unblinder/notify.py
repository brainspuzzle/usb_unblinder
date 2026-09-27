import shutil
import subprocess
import sys
import time


class Notifier:
    """Desktop notifications. Device strings are attacker-controlled, so they are
    passed as argv - never interpolated into a script."""

    COOLDOWN = 60

    def __init__(self, enabled=True):
        self.last = {}
        self.method = None
        if not enabled:
            return
        if sys.platform == "darwin" and shutil.which("osascript"):
            self.method = "osascript"
        elif sys.platform.startswith("linux") and shutil.which("notify-send"):
            self.method = "notify-send"

    @property
    def available(self):
        return self.method is not None

    def send(self, key, title, message):
        now = time.monotonic()
        if not self.method or now - self.last.get(key, -self.COOLDOWN) < self.COOLDOWN:
            return
        self.last[key] = now
        if self.method == "osascript":
            cmd = ["osascript", "-e", "on run argv",
                   "-e", "display notification (item 2 of argv) with title (item 1 of argv) sound name \"Basso\"",
                   "-e", "end run", title, message]
        else:
            cmd = ["notify-send", "-u", "critical", "--", title, message]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
