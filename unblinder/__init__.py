from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "unblinder.db"


def create_monitor(db_path=DEFAULT_DB, notify=True, poll_interval=None):
    from .backends import detect_backend
    from .monitor import Monitor
    from .notify import Notifier
    from .store import Store
    return Monitor(detect_backend(), Store(str(db_path)), Notifier(notify), poll_interval)
