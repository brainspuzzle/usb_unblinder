"""Read-only inspection of a mounted USB volume. Nothing on the volume is executed or opened
by an application; files are only stat()-ed, their first bytes read, and suspicious ones hashed."""
import hashlib
import os
import stat

MAX_ENTRIES = 2000
MAX_DEPTH = 3
MAX_HASH_BYTES = 64 * 1024 * 1024
SKIP_DIRS = {".Spotlight-V100", ".fseventsd", ".Trashes", ".TemporaryItems", "System Volume Information", "$RECYCLE.BIN"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".hta", ".msi", ".jar", ".sh", ".command", ".tool", ".app", ".pkg", ".dmg",
            ".py", ".pl", ".rb", ".scpt", ".applescript", ".workflow", ".elf", ".bin", ".run",
            ".desktop", ".lnk", ".url", ".inf", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".appimage", ".deb", ".rpm"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png",
           ".gif", ".mp3", ".mp4", ".mov", ".zip", ".rtf", ".csv", ".heic"}
AUTORUN = {"autorun.inf", "desktop.ini", ".autorun", "autorun.sh", ".autostart"}


def _magic(head):
    if head.startswith(b"MZ"):
        return "Windows executable (PE)"
    if head.startswith(b"\x7fELF"):
        return "Linux executable (ELF)"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "macOS executable (Mach-O)"
    if head.startswith(b"#!"):
        return "script (" + head[2:40].split(b"\n")[0].decode("utf-8", "replace").strip() + ")"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows shortcut (LNK)"
    return None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_volume(mountpoint, fstype=None):
    fat_like = (fstype or "").lower() in ("msdos", "exfat", "vfat", "fat32", "fat", "ntfs")
    report = {"mountpoint": mountpoint, "fstype": fstype, "entries": 0, "truncated": False,
              "total_bytes": 0, "flagged": [], "tree": []}
    root_depth = mountpoint.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(mountpoint, followlinks=False):
        depth = dirpath.count(os.sep) - root_depth
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and depth < MAX_DEPTH]
        for name in dirnames + filenames:
            if report["entries"] >= MAX_ENTRIES:
                report["truncated"] = True
                return report
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, mountpoint)
            try:
                st = os.lstat(path)
            except OSError as e:
                report["tree"].append({"path": rel, "error": str(e)})
                continue
            report["entries"] += 1
            is_dir = stat.S_ISDIR(st.st_mode)
            entry = {"path": rel, "dir": is_dir, "size": st.st_size, "mtime": int(st.st_mtime),
                     "hidden": name.startswith(".") and name not in (".DS_Store",)}
            if stat.S_ISLNK(st.st_mode):
                entry["symlink_to"] = os.readlink(path)
            report["tree"].append(entry)
            if is_dir:
                if name.lower().endswith((".app", ".workflow")):
                    report["flagged"].append({**entry, "reasons": ["application bundle"]})
                continue
            report["total_bytes"] += st.st_size

            reasons = []
            ext = os.path.splitext(name)[1].lower()
            if name.lower() in AUTORUN:
                reasons.append("autorun file")
            if ext in EXEC_EXT:
                reasons.append(f"executable/script extension {ext}")
            if not fat_like and st.st_mode & 0o111 and stat.S_ISREG(st.st_mode):
                reasons.append("executable permission bit")
            head = b""
            if stat.S_ISREG(st.st_mode):
                try:
                    with open(path, "rb") as f:
                        head = f.read(64)
                except OSError:
                    pass
            kind = _magic(head)
            if kind:
                entry["content"] = kind
                reasons.append(f"content is {kind}")
                if ext in DOC_EXT or (ext and ext not in EXEC_EXT):
                    reasons.append(f"disguised: {ext or 'no'} extension but {kind}")
            if entry["hidden"] and (kind or ext in EXEC_EXT):
                reasons.append("hidden executable")
            if reasons:
                if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_HASH_BYTES:
                    try:
                        entry["sha256"] = _sha256(path)
                    except OSError as e:
                        entry["sha256_error"] = str(e)
                report["flagged"].append({**entry, "reasons": reasons})
    return report
