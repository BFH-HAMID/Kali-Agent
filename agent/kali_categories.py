"""Kali package categories and the keyword classifier used by the registry.

Kali groups its tools in the ``kali-tools-*`` metapackages (info-gathering, web,
wireless, password, exploitation, sniffing-spoofing, forensics, reverse
engineering, post-exploitation, reporting).  We use the same taxonomy so the
model can reason in the categories it already knows.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

#: category -> one-line description shown by ``list_tool_categories``.
CATEGORIES: dict[str, str] = {
    "recon": "Information gathering / OSINT / DNS / port scanning (nmap, whois, theharvester)",
    "web": "Web application testing and fuzzing (nikto, gobuster, sqlmap, burpsuite)",
    "wireless": "Wi-Fi / Bluetooth / RFID attacks (aircrack-ng, wifite, reaver, bettercap)",
    "passwords": "Password cracking, wordlists and online attacks (hashcat, john, hydra)",
    "exploit": "Exploitation frameworks and vulnerability scanners (metasploit, searchsploit, nuclei)",
    "sniff-spoof": "Packet capture and MITM / spoofing (wireshark, tcpdump, ettercap)",
    "forensics": "Forensics and incident response (sleuthkit, volatility, binwalk, foremost)",
    "reverse": "Reverse engineering and binary analysis (radare2, ghidra, gdb, objdump)",
    "post-exploit": "Post exploitation, pivoting and C2 (empire, chisel, crackmapexec)",
    "reporting": "Documentation, reporting and note taking (dradis, cherrytree)",
    "misc": "Utilities that do not fit another category",
}

#: Kali metapackage suffix -> category (used as a strong hint during scanning).
METAPACKAGE_CATEGORIES: dict[str, str] = {
    "kali-tools-information-gathering": "recon",
    "kali-tools-vulnerability": "exploit",
    "kali-tools-web": "web",
    "kali-tools-passwords": "passwords",
    "kali-tools-wireless": "wireless",
    "kali-tools-exploitation": "exploit",
    "kali-tools-social-engineering": "exploit",
    "kali-tools-sniffing-spoofing": "sniff-spoof",
    "kali-tools-post-exploitation": "post-exploit",
    "kali-tools-forensics": "forensics",
    "kali-tools-reverse-engineering": "reverse",
    "kali-tools-reporting": "reporting",
    "kali-tools-hardware": "misc",
    "kali-tools-crypto-stego": "forensics",
    "kali-tools-fuzzing": "web",
    "kali-tools-debugging": "reverse",
    "kali-tools-rfid": "wireless",
    "kali-tools-sdr": "wireless",
    "kali-tools-voip": "sniff-spoof",
    "kali-tools-windows-resources": "post-exploit",
    "kali-tools-top10": "misc",
    "kali-linux-headless": "misc",
    "kali-linux-default": "misc",
}

#: Keyword -> category, checked against "<name> <description>".
#: Order matters: the first category that matches wins, later ones add weight.
CATEGORY_KEYWORDS: Mapping[str, tuple[str, ...]] = {
    "recon": (
        "scan", "scanner", "port", "dns", "domain", "subdomain", "osint",
        "whois", "reconnaissance", "recon", "enumeration", "enumerate",
        "footprint", "geolocation", "shodan", "certificate", "host discovery",
        "network mapper", "traceroute", "banner",
    ),
    "web": (
        "web", "http", "https", "url", "cms", "wordpress", "joomla", "drupal",
        "sql injection", "sqli", "xss", "fuzz", "directory", "brute force web",
        "crawler", "spider", "graphql", "api testing", "waf", "proxy interception",
        "burp", "browser", "xpath", "ldap injection", "web shell",
    ),
    "wireless": (
        "wireless", "wifi", "wi-fi", "802.11", "bluetooth", "rfid", "nfc",
        "sdr", "software defined radio", "zigbee", "gsm", "access point",
        "deauth", "handshake", "wpa", "wep", "wardriving",
    ),
    "passwords": (
        "password", "hash", "crack", "wordlist", "credential", "brute",
        "bruteforce", "dictionary", "kerberos", "ntlm", "rainbow", "john",
        "hashcat", "login attack", "pass-the-hash",
    ),
    "exploit": (
        "exploit", "exploitation", "payload", "metasploit", "shellcode",
        "vulnerability", "cve", "remote code", "0day", "fuzzer",
        "social engineering", "phishing", "trojan",
    ),
    "sniff-spoof": (
        "sniff", "sniffer", "spoof", "mitm", "man in the middle", "packet",
        "pcap", "capture", "arp", "dns spoof", "sslstrip", "network analysis",
        "voip", "sip", "tcpdump", "wireshark",
    ),
    "forensics": (
        "forensic", "evidence", "memory image", "disk image", "steganography",
        "stego", "carving", "recover deleted", "incident response", "artifact",
        "timeline", "registry hive", "mobile forensics", "autopsy", "sleuthkit",
        "volatility", "exif",
    ),
    "reverse": (
        "reverse engineering", "disassembler", "decompiler", "debugger",
        "binary analysis", "hex editor", "assembler", "elf", "firmware",
        "radare", "ghidra", "objdump", "gdb", "malware analysis",
    ),
    "post-exploit": (
        "post exploitation", "privilege escalation", "privesc", "lateral",
        "pivot", "c2", "command and control", "backdoor", "persistence",
        "mimikatz", "crackmapexec", "bloodhound", "impacket", "tunneling",
    ),
    "reporting": (
        "report", "reporting", "note", "documentation", "diagram", "mind map",
        "collaboration", "knowledge base",
    ),
}

#: Tools that are famous enough that a plain description match is not needed.
KNOWN_TOOLS: Mapping[str, str] = {
    "nmap": "recon", "masscan": "recon", "rustscan": "recon", "amass": "recon",
    "subfinder": "recon", "dnsenum": "recon", "dnsrecon": "recon",
    "whois": "recon", "theharvester": "recon", "recon-ng": "recon",
    "netdiscover": "recon", "arp-scan": "recon", "nbtscan": "recon",
    "nikto": "web", "gobuster": "web", "feroxbuster": "web", "ffuf": "web",
    "sqlmap": "web", "wpscan": "web", "dirb": "web", "dirsearch": "web",
    "burpsuite": "web", "whatweb": "web", "wafw00f": "web", "nuclei": "web",
    "commix": "web", "xsser": "web", "dotdotpwn": "web", "wfuzz": "web",
    "aircrack-ng": "wireless", "airodump-ng": "wireless", "wifite": "wireless",
    "reaver": "wireless", "kismet": "wireless", "bettercap": "sniff-spoof",
    "hashcat": "passwords", "john": "passwords", "hydra": "passwords",
    "medusa": "passwords", "crunch": "passwords", "cewl": "passwords",
    "ophcrack": "passwords", "ncrack": "passwords", "seclists": "passwords",
    "metasploit-framework": "exploit", "msfconsole": "exploit",
    "searchsploit": "exploit", "exploitdb": "exploit", "msfpc": "exploit",
    "setoolkit": "exploit", "beef-xss": "exploit",
    "wireshark": "sniff-spoof", "tcpdump": "sniff-spoof", "ettercap": "sniff-spoof",
    "dsniff": "sniff-spoof", "responder": "sniff-spoof", "mitmproxy": "sniff-spoof",
    "sleuthkit": "forensics", "autopsy": "forensics", "volatility3": "forensics",
    "binwalk": "forensics", "foremost": "forensics", "scalpel": "forensics",
    "exiftool": "forensics", "steghide": "forensics", "forensicmft": "forensics",
    "radare2": "reverse", "ghidra": "reverse", "gdb": "reverse",
    "objdump": "reverse", "rizin": "reverse", "gdb-multiarch": "reverse",
    "immunitydebugger": "reverse", "apktool": "reverse", "jadx": "reverse",
    "impacket-scripts": "post-exploit", "crackmapexec": "post-exploit",
    "bloodhound": "post-exploit", "chisel": "post-exploit",
    "powersploit": "post-exploit", "mimikatz": "post-exploit",
    "cherrytree": "reporting", "dradis": "reporting", "cutycapt": "reporting",
}

_SPLIT_RE = re.compile(r"[^a-z0-9+.\-]+")


def _normalise(text: str) -> str:
    return _SPLIT_RE.sub(" ", text.lower()).strip()


def classify(name: str, description: str = "", package: str = "") -> str:
    """Return the best category for a tool.

    Order of precedence:

    1. exact match in :data:`KNOWN_TOOLS`
    2. keyword hit on the tool name (strongest)
    3. keyword hits on the description
    4. ``"misc"``
    """

    for candidate in (name.lower(), package.lower()):
        if candidate in KNOWN_TOOLS:
            return KNOWN_TOOLS[candidate]

    haystack_name = _normalise(name)
    haystack_desc = _normalise(description)
    tokens_name = set(haystack_name.split())
    tokens_desc = set(haystack_desc.split())

    scores: dict[str, int] = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = 0
        for keyword in keywords:
            if " " in keyword:
                if keyword in haystack_desc:
                    score += 3
            else:
                if keyword in tokens_name:
                    score += 6
                elif keyword in tokens_desc:
                    score += 2
        if score:
            scores[category] = score

    if not scores:
        return "misc"
    return max(scores.items(), key=lambda kv: kv[1])[0]


def category_from_metapackage(metapackage: str) -> str | None:
    """Map a ``kali-tools-*`` metapackage name to a category."""

    return METAPACKAGE_CATEGORIES.get(metapackage.strip().lower())


def describe(category: str) -> str:
    """Description of a category, or a generic fallback."""

    return CATEGORIES.get(category, CATEGORIES["misc"])


def count_by_category(tools: Iterable[Mapping[str, object]]) -> dict[str, int]:
    """Count tools per category (used by ``list_tool_categories``)."""

    counts: dict[str, int] = {c: 0 for c in CATEGORIES}
    for tool in tools:
        cat = str(tool.get("category") or "misc")
        counts[cat] = counts.get(cat, 0) + 1
    return counts
