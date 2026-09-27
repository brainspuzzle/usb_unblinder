import platform
import sys


def detect_backend():
    """Pick the device backend for the OS we are running on."""
    if sys.platform == "darwin":
        from .macos import MacOSBackend
        return MacOSBackend()
    if sys.platform.startswith("linux"):
        from .linux import LinuxBackend
        return LinuxBackend()
    if sys.platform.startswith("win"):
        from .windows import WindowsBackend
        return WindowsBackend()
    raise RuntimeError(f"Unsupported platform: {sys.platform} ({platform.platform()})")
