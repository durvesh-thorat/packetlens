"""Reproducibility metadata helpers using only the Python standard library."""
import hashlib
import importlib.metadata
import platform
from datetime import datetime, timezone
from pathlib import Path


_MANIFEST_CACHE = {}


def dataset_manifest(paths):
    files = []
    seen = set()
    for value in paths:
        path = Path(value)
        name = path.name
        if name in seen:
            continue
        seen.add(name)
        if not path.is_file():
            files.append({"name": name, "status": "missing", "size_bytes": None, "sha256": None})
            continue
        stat = path.stat()
        cache_key = (str(path.resolve()), stat.st_size, stat.st_mtime_ns)
        if cache_key in _MANIFEST_CACHE:
            files.append(_MANIFEST_CACHE[cache_key])
            continue
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        record = {
            "name": name,
            "status": "available",
            "size_bytes": stat.st_size,
            "sha256": digest.hexdigest(),
        }
        _MANIFEST_CACHE[cache_key] = record
        files.append(record)
    return files


def build_meta(command_line, dataset_files=(), seeds=None, skipped=()):
    versions = {"python": platform.python_version()}
    for package in ("numpy", "pandas", "scikit-learn"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    return {
        "command_line": command_line,
        "utc_time": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "versions": versions,
        "seeds": seeds or {},
        "dataset_files": dataset_manifest(dataset_files),
        "skipped": list(skipped),
    }
