"""Safety layer: destructive-command filter and target scope enforcement.

Two independent gates run before every shell command the model asks for:

1. **Destructive command blocklist** - a set of regular expressions (plus a
   structural check for ``rm`` flags/targets) covering the classic footguns:
   ``rm -rf /``, ``mkfs``, ``dd`` onto a block device, fork bombs,
   ``chmod -R 777 /``, overwriting critical ``/etc`` files, disk wipers,
   wiping logs and rebooting the box.  A hit does not block the command
   outright, it forces an explicit ``yes`` from the user.
2. **Scope check** - every IP / CIDR / hostname found in the command is matched
   against the active scope (``set_scope``).  Anything outside the scope also
   needs an explicit ``yes``.

``SafetyGuard.check()`` is pure and easy to unit test; ``SafetyGuard.gate()``
adds the interactive confirmation round-trip supplied by the UI.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

#: Callback used to ask the human a yes/no question. Returns True for "yes".
AskFn = Callable[[str], bool]

# --------------------------------------------------------------------------
# Destructive command patterns
# --------------------------------------------------------------------------

#: ``(pattern, human readable reason)`` pairs.
DESTRUCTIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), reason)
    for pattern, reason in (
        (
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            "fork bomb",
        ),
        (
            r"\bmkfs(\.\w+)?\b",
            "formatting a filesystem (mkfs) destroys all data on the device",
        ),
        (
            r"\bdd\b[^\n]*\bof=/dev/(?:sd|hd|vd|nvme|mmcblk|xvd|dm-|md|loop)",
            "dd writing directly to a block device destroys the disk",
        ),
        (
            r">\s*/dev/(?:sd|hd|vd|nvme|mmcblk|xvd)",
            "redirecting output onto a raw block device destroys the disk",
        ),
        (
            r"\b(?:wipefs|blkdiscard)\b",
            "wiping filesystem or device signatures destroys data",
        ),
        (
            r"\bshred\b[^\n]*/dev/",
            "shredding a block device destroys data",
        ),
        (
            r"\bsgdisk\b[^\n]*--zap-all",
            "zapping a GPT partition table destroys data",
        ),
        (
            r"\bchmod\s+(?:-R\s+|--recursive\s+)*(?:0?777|a\+rwx)\s+/(?:\s|$|\*)",
            "chmod 777 on / removes all access control on the system",
        ),
        (
            r"\bchown\s+(?:-R\s+|--recursive\s+)[^\n]*\s/(?:\s|$)",
            "recursively chowning / can break the whole system",
        ),
        (
            r"(?:>>?\s*|tee\s+(?:-a\s+)?|cp\s+[^\n]*\s+)"
            r"/etc/(?:passwd|shadow|gshadow|group|sudoers(?:\.d/[^\s;|&]+)?|"
            r"fstab|hosts|resolv\.conf|pam\.d/[^\s;|&]+|ssh/sshd_config)",
            "overwriting a critical /etc file can lock you out of the machine",
        ),
        (
            r"\b(?:shutdown|poweroff|halt|reboot)\b(?!-)",
            "shutting down or powering off the machine",
        ),
        (
            r"\bsystemctl\s+(?:reboot|poweroff|halt|suspend|hibernate)\b",
            "shutting down or powering off the machine",
        ),
        (
            r"\binit\s+[06]\b",
            "rebooting or halting the machine",
        ),
        (
            r"\bkill\s+-9\s+1\b|\bkillall5\b",
            "killing PID 1 halts the machine",
        ),
        (
            r"\bhistory\s+-c\b|\bjournalctl\s+--?vacuum\b|"
            r"\btruncate\s+-s\s*0\s+/var/log|>\s*/var/log/[^\s;|&]+",
            "wiping logs destroys audit evidence",
        ),
        (
            r"\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
            "piping a remote download straight into a shell is unverifiable",
        ),
        (
            r"\b(?:iptables|nft)\s+-F\b|\bufw\s+disable\b|\biptables\s+-P\s+\w+\s+DROP",
            "flushing firewall rules can expose the machine",
        ),
    )
)

#: Directories where a recursive delete always needs confirmation.
CRITICAL_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/boot",
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/dev",
    "/proc",
    "/sys",
    "/var/lib",
    "/var/log",
    "/root",
)

#: Whole trees whose recursive removal is catastrophic.
DANGEROUS_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/root",
        "/home",
        "/etc",
        "/usr",
        "/var",
        "/boot",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/opt",
        "/srv",
        "/dev",
        "/proc",
        "/sys",
        "~",
        "$HOME",
        "${HOME}",
        "*",
    }
)

_RM_RE = re.compile(r"(?:^|[\s;&|(`])rm\s+(?P<rest>[^\n;&|`]*)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Scope helpers
# --------------------------------------------------------------------------

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?P<rest>[^/?#]+)")

#: File extensions that must never be mistaken for a hostname.
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "txt", "log", "json", "jsonl", "xml", "yaml", "yml", "conf", "cfg",
        "ini", "sh", "bash", "py", "js", "ts", "php", "html", "htm", "css",
        "md", "csv", "tsv", "pcap", "pcapng", "cap", "zip", "gz", "tgz",
        "bz2", "xz", "tar", "7z", "rar", "deb", "rpm", "so", "bin", "img",
        "iso", "db", "sqlite", "sqlite3", "lst", "pot", "hash", "wordlist",
        "pem", "key", "crt", "csr", "cer", "elf", "exe", "dll", "out", "err",
        "rules", "rc", "service", "lock", "tmp", "bak", "old", "swp",
    }
)

#: Hosts that always count as in-scope (the machine itself).
LOCAL_HOSTS: frozenset[str] = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "0.0.0.0", "::1"}
)


def _looks_like_file(token: str) -> bool:
    if token.endswith("/"):
        return True
    if "/" in token or "\\" in token:
        return True
    if token.startswith((".", "~", "$", "%")):
        return True
    if "." in token:
        suffix = token.rsplit(".", 1)[-1].lower()
        if suffix in FILE_EXTENSIONS:
            return True
    return False


def _clean_token(token: str) -> str:
    token = token.strip().strip("'\"`")
    token = token.rstrip(",;:)")
    token = token.lstrip("([{")
    return token


def _as_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _as_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def normalise_target(target: str) -> str:
    """Expand shorthand (``~``, ``$HOME``) so comparisons are predictable."""

    target = target.strip().strip("'\"")
    if target in {"~", "~/"}:
        return "~"
    return target


def extract_targets(command: str) -> list[str]:
    """Return every IP, CIDR or hostname that a command appears to touch.

    Flags, paths, file names and obvious non-targets are ignored.  The parser
    is intentionally permissive: a false positive only costs the user one
    confirmation prompt, a false negative could scan the wrong network.
    """

    try:
        tokens = shlex.split(command, comments=True)
    except ValueError:
        tokens = command.split()

    found: list[str] = []

    def add(candidate: str) -> None:
        candidate = candidate.strip().strip("[]")
        if not candidate or candidate in found:
            return
        found.append(candidate)

    for raw in tokens:
        for token in raw.split(","):
            token = _clean_token(token)
            if not token:
                continue
            # --url=https://host/x  -> inspect the value only
            if token.startswith("-"):
                if "=" not in token:
                    continue
                token = _clean_token(token.split("=", 1)[1])
                if not token:
                    continue
            if token in LOCAL_HOSTS:
                continue
            if token.startswith("--"):
                continue

            url_match = URL_RE.match(token)
            if url_match:
                host = url_match.group("rest").split("@")[-1].split(":")[0]
                if host and not _looks_like_file(host):
                    add(host)
                continue

            # user@host:/path  or  user@host
            if "@" in token and "://" not in token:
                token = token.split("@")[-1]
                token = token.split(":")[0]

            # host:/path
            if token.count(":") == 1 and "/" in token:
                token = token.split(":", 1)[0]

            if IPV4_RE.match(token):
                network = _as_network(token)
                if network is not None and not network.is_loopback and not network.is_unspecified:
                    add(token)
                continue
            if ":" in token:  # bare IPv6
                try:
                    ipaddress.IPv6Address(token.split("/")[0])
                except ValueError:
                    continue
                add(token)
                continue
            if _looks_like_file(token):
                continue
            if DOMAIN_RE.match(token):
                add(token)

    return found


def scope_label(scope: Sequence[str]) -> str:
    """Human readable scope for status bars / prompts."""

    if not scope:
        return "unrestricted"
    return ", ".join(scope)


def is_in_scope(target: str, scope: Sequence[str]) -> bool:
    """True when ``target`` belongs to the active scope.

    An empty scope means "not configured yet" and allows everything - the agent
    is expected to call ``set_scope`` first (the system prompt enforces it).
    """

    if not scope:
        return True

    target = target.strip()
    if not target:
        return True
    if target.lower() in LOCAL_HOSTS:
        return True

    target_addr = _as_address(target)
    target_net = _as_network(target)

    if target_addr is not None:
        if target_addr.is_loopback or target_addr.is_unspecified:
            return True
    if target_net is not None:
        if target_net.is_loopback:
            return True

    for entry in scope:
        entry = entry.strip().lower()
        if not entry:
            continue

        entry_net = _as_network(entry)
        if entry_net is not None:
            if target_addr is not None and target_addr.version == entry_net.version:
                if target_addr in entry_net:
                    return True
            if target_net is not None and target_net.version == entry_net.version:
                if target_net.subnet_of(entry_net):
                    return True
            continue

        # hostname / wildcard entry
        host = entry.lstrip("*.").rstrip(".")
        low = target.lower()
        if entry.startswith("*."):
            if low == host or low.endswith("." + host):
                return True
        elif low == host or low.endswith("." + host):
            return True

    return False


def out_of_scope(targets: Iterable[str], scope: Sequence[str]) -> list[str]:
    """Filter ``targets`` down to the ones outside ``scope``."""

    return [t for t in targets if not is_in_scope(t, scope)]


# --------------------------------------------------------------------------
# rm analysis
# --------------------------------------------------------------------------

def _norm_path(path: str) -> str:
    path = path.strip().strip("'\"")
    if path in {"~", "$HOME", "${HOME}"}:
        return "~"
    if path.startswith("~/"):
        return "~"
    path = re.sub(r"\*+$", "", path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def _rm_risk(command: str) -> str | None:
    """Structural check of ``rm`` invocations (flags + targets)."""

    for match in _RM_RE.finditer(command):
        rest = match.group("rest").strip()
        if not rest:
            continue
        try:
            parts = shlex.split(rest)
        except ValueError:
            parts = rest.split()

        recursive = False
        targets: list[str] = []
        for part in parts:
            if part.startswith("-") and part != "-":
                flags = part.lstrip("-").lower()
                if part.startswith("--"):
                    if flags == "recursive":
                        recursive = True
                elif "r" in flags:
                    recursive = True
                continue
            targets.append(part)

        if not targets:
            continue

        for target in targets:
            norm = _norm_path(target)
            if norm in DANGEROUS_ROOTS:
                return f"recursive delete of {target!r} can destroy the system or home directory"
            if recursive:
                for prefix in CRITICAL_PREFIXES:
                    if norm == prefix or norm.startswith(prefix + "/"):
                        return f"recursive delete inside {prefix} can break the system"
    return None


def destructive_reasons(command: str) -> list[str]:
    """Return every destructive-pattern hit for ``command`` (may be empty)."""

    reasons: list[str] = []
    rm_reason = _rm_risk(command)
    if rm_reason:
        reasons.append(rm_reason)
    for pattern, reason in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------

@dataclass
class SafetyDecision:
    """Outcome of a safety evaluation for one command."""

    command: str
    allowed: bool = True
    needs_confirmation: bool = False
    reasons: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    denied_reason: str = ""

    def describe(self) -> str:
        bits = list(self.reasons)
        if self.out_of_scope:
            bits.append("target(s) outside scope: " + ", ".join(self.out_of_scope))
        return "; ".join(bits) if bits else "ok"


class SafetyGuard:
    """Destructive-command filter plus scope enforcement.

    Parameters
    ----------
    scope:
        Active scope entries (IPs, CIDR blocks, hostnames, ``*.wildcards``).
    ask:
        Callback used by :meth:`gate` to obtain a human decision. ``None``
        means "no human available", in which case risky commands are refused.
    """

    def __init__(
        self,
        scope: Sequence[str] | None = None,
        ask: AskFn | None = None,
    ) -> None:
        self._scope: list[str] = [s.strip() for s in (scope or []) if s.strip()]
        self._ask = ask

    # ------------------------------------------------------------- scope
    @property
    def scope(self) -> list[str]:
        return list(self._scope)

    def set_scope(self, scope: Sequence[str]) -> None:
        self._scope = [str(s).strip() for s in scope if str(s).strip()]

    def set_ask(self, ask: AskFn | None) -> None:
        self._ask = ask

    # ------------------------------------------------------------- checks
    def check(self, command: str) -> SafetyDecision:
        """Evaluate ``command`` without prompting anybody."""

        decision = SafetyDecision(command=command)
        decision.reasons = destructive_reasons(command)
        decision.targets = extract_targets(command)
        decision.out_of_scope = out_of_scope(decision.targets, self._scope)
        decision.needs_confirmation = bool(decision.reasons or decision.out_of_scope)
        decision.allowed = not decision.needs_confirmation
        return decision

    def gate(self, command: str) -> SafetyDecision:
        """Check ``command`` and, when required, ask the user for approval."""

        decision = self.check(command)
        if not decision.needs_confirmation:
            return decision

        if self._ask is None:
            decision.allowed = False
            decision.denied_reason = (
                "no interactive confirmation available: " + decision.describe()
            )
            return decision

        for reason in decision.reasons:
            question = (
                f"Safety: {reason}.\nCommand: {command}\nRun it anyway?"
            )
            if not self._ask(question):
                decision.allowed = False
                decision.denied_reason = f"user refused: {reason}"
                return decision

        if decision.out_of_scope:
            question = (
                "Scope: this command touches target(s) outside the active scope "
                f"({', '.join(decision.out_of_scope)}; scope = {scope_label(self._scope)}).\n"
                f"Command: {command}\nProceed anyway?"
            )
            if not self._ask(question):
                decision.allowed = False
                decision.denied_reason = (
                    "user refused out-of-scope targets: "
                    + ", ".join(decision.out_of_scope)
                )
                return decision

        decision.allowed = True
        return decision


__all__ = [
    "DESTRUCTIVE_PATTERNS",
    "SafetyDecision",
    "SafetyGuard",
    "destructive_reasons",
    "extract_targets",
    "is_in_scope",
    "normalise_target",
    "out_of_scope",
    "scope_label",
]
