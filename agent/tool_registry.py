"""Kali tool registry: scan the whole toolset, search it, read help, install.

The catalog is built once and cached in
``~/.config/kali-agent/tools_catalog.json``.  Sources, in order of preference:

* ``apt-cache depends kali-linux-everything`` -> ``kali-tools-*`` metapackages
  -> their dependencies (the full Kali tool list, installed or not)
* ``dpkg-query`` for what is actually installed right now
* ``/usr/local/bin`` and ``/opt/*/bin`` for locally installed extras
* ``/usr/bin`` + ``/usr/sbin`` to resolve which executable a package provides

Everything degrades gracefully: on a machine without ``apt``/``dpkg`` the
registry simply falls back to scanning the binary directories.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import kali_categories
from .config import CATALOG_FILE
from .executor import CommandExecutor

PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,80}$")
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07]*\x07")

#: Max entries kept in the catalog (guards against a runaway apt database).
MAX_TOOLS = 4000

#: How many characters of ``--help`` output ``tool_help`` returns.
HELP_MAX_CHARS = 6000

#: Binaries that are never interesting as "Kali tools".
BORING_BINARIES = frozenset(
    {
        "apt", "apt-get", "apt-cache", "dpkg", "dpkg-query", "bash", "sh",
        "dash", "ls", "cp", "mv", "rm", "mkdir", "rmdir", "cat", "echo",
        "grep", "egrep", "fgrep", "sed", "awk", "gawk", "find", "xargs",
        "which", "whereis", "env", "true", "false", "sleep", "touch", "ln",
        "chmod", "chown", "chgrp", "stat", "du", "df", "free", "ps", "kill",
        "killall", "top", "less", "more", "head", "tail", "sort", "uniq",
        "wc", "cut", "tr", "tee", "date", "cal", "id", "whoami", "who",
        "uname", "hostname", "uptime", "mount", "umount", "sudo", "su",
        "passwd", "useradd", "usermod", "userdel", "groupadd", "clear",
        "tput", "reset", "stty", "test", "expr", "seq", "yes", "timeout",
        "printf", "readlink", "realpath", "basename", "dirname", "mktemp",
        "nohup", "pwd", "cd", "alias", "unalias", "history", "shopt",
        "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "diff",
        "patch", "md5sum", "sha1sum", "sha256sum", "base64", "xxd",
        "python3", "perl", "node", "vim", "nano", "vi", "man", "info",
        "git", "make", "gcc", "cc", "ld", "strings", "file", "ltrace",
        "strace", "time", "watch", "screen", "tmux", "ssh-keygen",
        "systemctl", "service", "journalctl", "dmesg", "lsblk", "fdisk",
        "parted", "lsof", "iostat", "vmstat", "netstat", "ss", "ping",
    }
)


def _clean(text: str) -> str:
    text = ANSI_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class ToolEntry:
    """One entry in the Kali tool catalog."""

    name: str
    package: str = ""
    binary: str = ""
    installed: bool = False
    description: str = ""
    category: str = "misc"
    path: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ToolEntry:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})  # type: ignore[arg-type]

    def as_payload(self) -> dict[str, object]:
        """Compact dict shown to the model."""

        payload: dict[str, object] = {
            "name": self.name,
            "installed": self.installed,
            "category": self.category,
            "description": self.description[:180],
        }
        if self.binary and self.binary != self.name:
            payload["binary"] = self.binary
        if self.package and self.package != self.name:
            payload["package"] = self.package
        if self.path:
            payload["path"] = self.path
        return payload


class ToolRegistry:
    """Scan, search, read help for, and install Kali tools."""

    def __init__(
        self,
        catalog_path: str | Path = CATALOG_FILE,
        *,
        executor: CommandExecutor | None = None,
        timeout: float = 90.0,
    ) -> None:
        self.catalog_path = Path(catalog_path)
        self.executor = executor
        self.timeout = timeout
        self.tools: dict[str, ToolEntry] = {}
        self.generated_at: str = ""
        self._binaries: set[str] = set()
        self._bin_cache: dict[str, str] = {}

    # ------------------------------------------------------------------ io
    def _run(self, args: Sequence[str], timeout: float | None = None) -> tuple[int, str]:
        """Small non-streaming helper for apt/dpkg queries."""

        try:
            proc = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            return 127, ""
        return proc.returncode, _clean(proc.stdout or proc.stderr or "")

    def load(self, *, force: bool = False, max_age_days: int = 7) -> bool:
        """Load the cached catalog, refreshing when missing/stale.

        Returns ``True`` when a fresh scan was performed.
        """

        if not force and self.catalog_path.exists():
            try:
                raw = json.loads(self.catalog_path.read_text(encoding="utf-8"))
                entries = raw.get("tools", {})
                self.tools = {
                    name: ToolEntry.from_dict(data) for name, data in entries.items()
                }
                self.generated_at = str(raw.get("generated_at", ""))
            except (OSError, json.JSONDecodeError, TypeError):
                self.tools = {}
            if self.tools:
                age = self._age_days()
                if age is None or age <= max_age_days:
                    self._index_binaries()
                    return False
        self.scan()
        return True

    def _age_days(self) -> float | None:
        if not self.generated_at:
            return None
        try:
            stamp = datetime.fromisoformat(self.generated_at)
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return (datetime.now(UTC) - stamp).total_seconds() / 86400.0

    def save(self) -> Path:
        self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": self.generated_at or _now(),
            "count": len(self.tools),
            "tools": {name: entry.to_dict() for name, entry in self.tools.items()},
        }
        self.catalog_path.write_text(
            json.dumps(payload, indent=1), encoding="utf-8"
        )
        try:
            os.chmod(self.catalog_path, 0o600)
        except OSError:  # pragma: no cover
            pass
        return self.catalog_path

    # -------------------------------------------------------------- scanning
    def scan(self, on_status: Callable[[str], None] | None = None) -> dict[str, object]:
        """Rebuild the catalog from apt, dpkg and the filesystem."""

        def note(message: str) -> None:
            if on_status is not None:
                try:
                    on_status(message)
                except Exception:
                    pass

        note("scanning installed packages (dpkg)...")
        installed = self._dpkg_installed()

        note("scanning Kali metapackages (apt)...")
        available = self._apt_available()

        note("indexing binaries...")
        binaries, local_binaries = self._scan_binaries()

        entries: dict[str, ToolEntry] = {}

        for package in sorted(set(available) | set(installed)):
            if len(entries) >= MAX_TOOLS:
                break
            if not PACKAGE_NAME_RE.match(package):
                continue
            description = installed.get(package) or available.get(package) or ""
            binary = self._pick_binary(package, binaries)
            entry = ToolEntry(
                name=package,
                package=package,
                binary=binary,
                installed=package in installed,
                description=description,
                category=kali_categories.classify(package, description, package),
            )
            if binary:
                entry.path = shutil.which(binary) or ""
            entries[package] = entry

        # locally installed tools that no package claims
        for binary in sorted(local_binaries):
            if binary in entries or binary in BORING_BINARIES:
                continue
            if not PACKAGE_NAME_RE.match(binary):
                continue
            path = shutil.which(binary) or ""
            entries[binary] = ToolEntry(
                name=binary,
                package="",
                binary=binary,
                installed=True,
                description="locally installed tool",
                category=kali_categories.classify(binary, "", ""),
                path=path,
            )

        self.tools = entries
        self._binaries = binaries
        self._bin_cache.clear()
        self.generated_at = _now()
        self.save()

        stats = self.stats()
        note(
            f"catalog ready: {stats['installed']} installed / "
            f"{stats['available']} available tools"
        )
        return stats

    def _dpkg_installed(self) -> dict[str, str]:
        if not shutil.which("dpkg-query"):
            return {}
        formats = (
            "${db:Status-Abbrev}\\t${binary:Package}\\t${binary:Summary}\\n",
            "${Status}\\t${binary:Package}\\t${Description}\\n",
        )
        for fmt in formats:
            code, out = self._run(["dpkg-query", "-W", f"-f={fmt}"])
            if code != 0 or not out.strip():
                continue
            result: dict[str, str] = {}
            for line in out.splitlines():
                parts = line.split("\t", 2)
                if len(parts) < 2:
                    continue
                status, package = parts[0].strip(), parts[1].strip()
                description = parts[2].strip() if len(parts) > 2 else ""
                description = description.split("\n")[0]
                if not package:
                    continue
                if status.startswith("ii") or "install ok installed" in status:
                    result[package] = description
            if result:
                return result
        return {}

    def _apt_available(self) -> dict[str, str]:
        if not shutil.which("apt-cache"):
            return {}

        metapackages: set[str] = set()
        for root in ("kali-linux-everything", "kali-linux-default", "kali-tools-top10"):
            code, out = self._run(["apt-cache", "depends", root], timeout=45)
            if code == 0 and out.strip():
                for name in self._parse_depends(out):
                    metapackages.add(name)
                if metapackages:
                    break

        packages: set[str] = set()
        for meta in sorted(metapackages):
            if len(packages) > MAX_TOOLS:
                break
            code, out = self._run(["apt-cache", "depends", meta], timeout=45)
            if code != 0:
                continue
            packages.update(self._parse_depends(out))

        if not packages:
            return {}

        descriptions: dict[str, str] = {}
        ordered = sorted(packages)
        for start in range(0, len(ordered), 80):
            chunk = ordered[start : start + 80]
            code, out = self._run(["apt-cache", "show", *chunk], timeout=60)
            if code == 0 and out:
                descriptions.update(self._parse_show(out))
        for package in ordered:
            descriptions.setdefault(package, "")
        return descriptions

    @staticmethod
    def _parse_depends(text: str) -> set[str]:
        names: set[str] = set()
        for line in text.splitlines():
            stripped = line.strip().lstrip("|").strip()
            if not stripped.lower().startswith(("depends:", "pre-depends:")):
                continue
            name = stripped.split(":", 1)[1].strip().split(":")[0].strip()
            name = name.split(" ")[0].strip("()<>")
            if PACKAGE_NAME_RE.match(name):
                names.add(name)
        return names

    @staticmethod
    def _parse_show(text: str) -> dict[str, str]:
        result: dict[str, str] = {}
        current: str | None = None
        for line in text.splitlines():
            if line.startswith("Package:"):
                current = line.split(":", 1)[1].strip()
                result.setdefault(current, "")
            elif current and line.lower().startswith("description-en:"):
                if not result[current]:
                    result[current] = line.split(":", 1)[1].strip()
            elif current and line.lower().startswith("description:"):
                if not result[current]:
                    result[current] = line.split(":", 1)[1].strip()
        return result

    def _scan_binaries(self) -> tuple[set[str], set[str]]:
        """Return (all PATH binaries, locally installed binaries)."""

        binaries: set[str] = set()
        local: set[str] = set()
        local_dirs = ("/usr/local/bin", "/usr/local/sbin")

        for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", *local_dirs):
            path = Path(directory)
            if not path.is_dir():
                continue
            try:
                for item in os.scandir(path):
                    if not item.is_file():
                        continue
                    if not os.access(item.path, os.X_OK):
                        continue
                    binaries.add(item.name)
                    if directory in local_dirs:
                        local.add(item.name)
            except OSError:
                continue

        # /opt/*/bin (e.g. burpsuite, ghidra)
        opt = Path("/opt")
        if opt.is_dir():
            try:
                for vendor in opt.iterdir():
                    bin_dir = vendor / "bin"
                    if not bin_dir.is_dir():
                        continue
                    for item in os.scandir(bin_dir):
                        if item.is_file() and os.access(item.path, os.X_OK):
                            binaries.add(item.name)
                            local.add(item.name)
            except OSError:
                pass

        # also consider anything currently on PATH (venvs, ~/.local/bin)
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if not directory or not os.path.isdir(directory):
                continue
            try:
                for item in os.scandir(directory):
                    if item.is_file() and os.access(item.path, os.X_OK):
                        binaries.add(item.name)
            except OSError:
                continue

        return binaries, local

    @staticmethod
    def _pick_binary(package: str, binaries: Iterable[str]) -> str:
        binary_set = binaries if isinstance(binaries, set) else set(binaries)
        if package in binary_set:
            return package
        for candidate in (package.replace("-", ""), package.replace("-", "_")):
            if candidate in binary_set:
                return candidate
        return package

    def _index_binaries(self) -> None:
        if not self._binaries:
            self._binaries, _ = self._scan_binaries()

    # --------------------------------------------------------------- queries
    def stats(self) -> dict[str, object]:
        installed = sum(1 for t in self.tools.values() if t.installed)
        return {
            "installed": installed,
            "available": len(self.tools),
            "generated_at": self.generated_at or "",
        }

    def counts(self) -> tuple[int, int]:
        installed = sum(1 for t in self.tools.values() if t.installed)
        return installed, len(self.tools)

    def get(self, name: str) -> ToolEntry | None:
        name = name.strip().lower()
        if name in self.tools:
            return self.tools[name]
        for entry in self.tools.values():
            if entry.binary.lower() == name or entry.package.lower() == name:
                return entry
        return None

    def categories(self) -> dict[str, dict[str, object]]:
        counts = kali_categories.count_by_category(t.to_dict() for t in self.tools.values())
        installed_by_cat: dict[str, int] = {}
        for entry in self.tools.values():
            if entry.installed:
                installed_by_cat[entry.category] = installed_by_cat.get(entry.category, 0) + 1
        return {
            category: {
                "description": description,
                "tools": counts.get(category, 0),
                "installed": installed_by_cat.get(category, 0),
            }
            for category, description in kali_categories.CATEGORIES.items()
        }

    def search(
        self,
        query: str,
        *,
        limit: int = 15,
        category: str | None = None,
        installed_only: bool = False,
    ) -> list[ToolEntry]:
        """Score the catalog against ``query`` and return the best matches."""

        query = (query or "").strip().lower()
        tokens = [t for t in re.split(r"[^a-z0-9+.\-]+", query) if t]
        scored: list[tuple[int, ToolEntry]] = []

        for entry in self.tools.values():
            if category and entry.category != category:
                continue
            if installed_only and not entry.installed:
                continue
            score = self._score(entry, query, tokens)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda item: (-item[0], item[1].name))
        return [entry for _, entry in scored[: max(1, limit)]]

    @staticmethod
    def _score(entry: ToolEntry, query: str, tokens: list[str]) -> int:
        name = entry.name.lower()
        binary = entry.binary.lower()
        package = entry.package.lower()
        description = entry.description.lower()
        score = 0

        if query:
            if query in (name, binary, package):
                score += 150
            elif len(query) >= 3 and (name.startswith(query) or binary.startswith(query)):
                score += 100
            elif len(query) >= 3 and (query in name or query in binary):
                score += 65
            elif len(query) >= 4 and query in description:
                score += 30

        for token in tokens:
            if token == name or token == binary:
                score += 40
            elif len(token) >= 4 and (token in name or token in binary):
                score += 25
            elif len(token) >= 4 and token in description:
                score += 8

        # only break ties between real matches - never invent one
        if score > 0 and entry.installed:
            score += 4
        return score

    def resolve_binary(self, name: str) -> str | None:
        """Find the executable that provides ``name``."""

        name = name.strip()
        if not name:
            return None
        if name in self._bin_cache:
            return self._bin_cache[name] or None

        found = shutil.which(name)
        if found:
            self._bin_cache[name] = found
            return found

        entry = self.get(name)
        if entry is not None and entry.path and Path(entry.path).exists():
            self._bin_cache[name] = entry.path
            return entry.path

        package = entry.package if entry else name
        if package and shutil.which("dpkg"):
            code, out = self._run(["dpkg", "-L", package], timeout=20)
            if code == 0:
                for line in out.splitlines():
                    candidate = line.strip()
                    if candidate.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
                        if os.access(candidate, os.X_OK):
                            self._bin_cache[name] = candidate
                            return candidate

        self._bin_cache[name] = ""
        return None

    # ------------------------------------------------------------------ help
    def help_text(self, name: str, max_chars: int = HELP_MAX_CHARS) -> dict[str, object]:
        """Return real ``--help`` / ``-h`` / man output for a tool."""

        entry = self.get(name)
        binary = self.resolve_binary(name)

        if binary is None:
            return {
                "error": f"'{name}' was not found on PATH.",
                "hint": "Try search_tools or install_tool first.",
                "installed": bool(entry and entry.installed),
            }

        attempts: list[list[str]] = [
            [binary, "--help"],
            [binary, "-h"],
            [binary, "help"],
            ["man", "-P", "cat", os.path.basename(binary)],
        ]

        for attempt in attempts:
            if attempt[0] == "man" and not shutil.which("man"):
                continue
            text = self._capture(attempt)
            if text and len(text.strip()) >= 40:
                text = text.strip()
                truncated = len(text) > max_chars
                return {
                    "tool": entry.name if entry else name,
                    "binary": binary,
                    "command": " ".join(attempt),
                    "help": text[:max_chars],
                    "truncated": truncated,
                }

        return {
            "error": f"no help output available for '{name}' ({binary}).",
            "hint": "The tool may need root, or its help lives in a GUI/man-only page.",
            "binary": binary,
        }

    def _capture(self, args: Sequence[str]) -> str:
        env = dict(os.environ)
        env.update(
            {
                "TERM": "dumb",
                "MANPAGER": "cat",
                "PAGER": "cat",
                "NO_COLOR": "1",
                "COLUMNS": "100",
            }
        )
        try:
            proc = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=12,
                stdin=subprocess.DEVNULL,
                env=env,
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        text = _clean((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))
        # tools sometimes dump binary-ish bytes
        return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch.isprintable())

    # --------------------------------------------------------------- install
    def install(
        self,
        name: str,
        on_line: Callable[[str], None] | None = None,
    ) -> dict[str, object]:
        """Install a package with apt (passwordless sudo expected)."""

        name = name.strip()
        if not PACKAGE_NAME_RE.match(name):
            return {"error": f"'{name}' is not a valid package name."}

        entry = self.get(name)
        package = entry.package if entry and entry.package else name

        if entry is None and self.tools:
            suggestions = [t.name for t in self.search(name, limit=5)]
            return {
                "error": f"'{name}' is not a known Kali package.",
                "did_you_mean": suggestions,
                "hint": "Use search_tools to find the right package name.",
            }

        if entry is not None and entry.installed and shutil.which(entry.binary or package):
            return {
                "status": "already_installed",
                "package": package,
                "binary": entry.binary,
            }

        command = (
            "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "-o Dpkg::Options::=--force-confold "
            + package
        )

        if self.executor is not None:
            result = self.executor.run(command, timeout=600)
            exit_code, output = result.exit_code, result.output
        else:
            if on_line is not None:
                on_line(f"$ {command}")
            try:
                proc = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=900,
                    errors="replace",
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return {"error": f"install failed: {exc}"}
            exit_code, output = proc.returncode, _clean(proc.stdout + proc.stderr)
            if on_line is not None:
                for line in output.splitlines():
                    on_line(line)

        if exit_code != 0:
            return {
                "error": f"apt-get failed with exit code {exit_code}",
                "package": package,
                "output": output[-3000:],
                "hint": "Is passwordless sudo configured? See README.",
            }

        if entry is not None:
            entry.installed = True
            entry.path = shutil.which(entry.binary or package) or entry.path
        else:
            binary = shutil.which(package)
            self.tools[package] = ToolEntry(
                name=package,
                package=package,
                binary=package,
                installed=True,
                description="installed on demand",
                category=kali_categories.classify(package, ""),
                path=binary or "",
            )
        self.save()
        return {
            "status": "installed",
            "package": package,
            "binary": self.resolve_binary(package) or package,
        }


__all__ = [
    "HELP_MAX_CHARS",
    "PACKAGE_NAME_RE",
    "ToolEntry",
    "ToolRegistry",
]
