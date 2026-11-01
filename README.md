# KaliAgent

**An autonomous AI security-operations agent that runs directly on your Kali Linux box.**

KaliAgent (Gemini API + manual function calling) plans the work, discovers the right
Kali tool, reads its real `--help`, installs it if missing, runs it, reads the output,
and decides the next step on its own — while **you watch every command stream live**.
A safety layer refuses destructive commands and out-of-scope targets unless you approve.

```
┌───────────────────────────────────── KaliAgent ─────────────────────────────────────┐
│ Tools: 612 installed / 640 available | Scope: 10.10.10.0/24 | gemini-2.5-pro | ready│
├───────────────────────────────┬─────────────────────────────────────────────────────┤
│ Agent · reasoning & answers   │ Live terminal                                       │
│ → search_tools (query=smb)    │ $ nmap -sV -p445,139 10.10.10.5                     │
│ → tool_help (name=enum4linux) │ Starting Nmap 7.94 ( https://nmap.org )             │
│ agent                         │ Nmap scan report for 10.10.10.5                     │
│   SMB is exposed; enumerating │ 445/tcp open  microsoft-ds  Windows Server 2019     │
│                               │ 139/tcp open  netbios-ssn                           │
├───────────────────────────────┴─────────────────────────────────────────────────────┤
│ Time     Exit  Duration  Command                                                    │
│ 21:14:02 0     12.4s     nmap -sV -p445,139 10.10.10.5                              │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ১. দ্রুত শুরু (Bangla quick start)

```bash
git clone <this-repo> kali-agent && cd kali-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Kali তে একবার passwordless sudo সেট করুন
echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/kali-agent
sudo chmod 440 /etc/sudoers.d/kali-agent

python main.py                     # প্রথমবার Gemini API key চাইবে (hidden input)
python main.py --scope 10.10.10.0/24
python main.py --tmux               # অন্য টার্মিনালে: tmux attach -t kali-agent
python main.py --unsafe             # Kali Live: কোনো confirmation ছাড়াই (persisted)
```

API key `~/.config/kali-agent/config.json` এ `chmod 600` দিয়ে সেভ হয় — কোনো `.env` নেই।

---

## 2. Features

| Topic | Decision |
| --- | --- |
| **AI** | Gemini API (`google-genai`), manual function-calling loop, automatic function calling **disabled** |
| **API key** | Asked once with a hidden prompt (`getpass`), stored in `~/.config/kali-agent/config.json`, `chmod 600`, no `.env` |
| **Tools** | The whole Kali toolset: auto-scan, search, read real `--help`, install missing packages |
| **Terminal** | Live streaming, timeouts, process-group kill, interactive programs via `pexpect` |
| **Live view** | Textual TUI, or `--tmux` mode (`tmux attach -t kali-agent`) |
| **sudo** | Passwordless — the agent can use `sudo` non-interactively |
| **Safety** | Destructive commands need confirmation; out-of-scope targets are refused unless approved |
| **Uncensored** | `--unsafe` (a.k.a. `--no-safety` / `--yolo`): no confirmation, no scope blocking — for Kali **Live** / disposable systems. Still fully logged |
| **Logs** | Every command, output, exit code and duration in `logs/<session>.jsonl` + Markdown report |
| **Memory** | Scope, notes, findings, command timeline; exported as Markdown on `finish` |

---

## 3. Requirements

* Kali Linux (any recent release) — Debian-based systems work too
* Python **3.10+**
* A **Gemini API key** — <https://aistudio.google.com/apikey>
* `tmux` (optional, only for `--tmux` mode)
* Passwordless sudo (recommended, one-time setup below)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Passwordless sudo (one time)

```bash
echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/kali-agent
sudo chmod 440 /etc/sudoers.d/kali-agent
```

Verify with `sudo -n true && echo ok`. Without this, `sudo` commands will block waiting for a
password (they are rejected by the agent's timeout instead of hanging forever).

---

## 4. Usage

```bash
python main.py                                   # TUI, empty chat
python main.py "enumerate SMB on 10.10.10.5"     # TUI with an initial task
python main.py --scope 10.10.10.0/24 example.com # authorised targets for this session
python main.py --plain                           # simple console mode (no Textual)
python main.py --tmux                            # every command runs in tmux
python main.py --rescan                          # rebuild the Kali tool catalog
python main.py --model gemini-2.5-flash          # switch model (remembered)
python main.py --reset-key                       # forget the stored API key
python main.py --max-steps 80 --timeout 600      # longer tasks / slower tools
python main.py --non-interactive "quick task"    # never prompt (needs a stored key)
python main.py --unsafe                          # uncensored mode (Kali Live)
python main.py --safe                            # restore the guards again
```

### TUI

| Area | Contents |
| --- | --- |
| Top status line | `Tools: N installed / M available | Scope: … | model | status` |
| Left pane | Agent reasoning, tool calls, final answers |
| Right pane | Live terminal output of the running command |
| Bottom table | Command history with exit code, duration and time |
| Input box | Your task — or `y`/`n` when the agent asks for approval |

Keys: `Esc` stop the running task · `Ctrl+R` rescan tools · `Ctrl+N` new chat ·
`Ctrl+T` toggle unsafe mode · `Ctrl+L` clear terminal · `Ctrl+Q` quit.

### tmux live mode

```bash
python main.py --tmux          # in terminal 1
tmux attach -t kali-agent      # in terminal 2 (watch, or type interactively)
```

Each command is pasted into the `kali-agent` session, piped through `tee`, so it is
visible live in the pane **and** captured for the agent/logs. Detach with `Ctrl+B D`.

### Console mode helpers

Inside `--plain`/`--tmux` mode: `exit` quits, `help` lists helpers,
`scope 10.0.0.0/24 example.com` updates the scope without asking the model.

---

## 5. Tools the model can call

| Tool | Purpose |
| --- | --- |
| `run_command(cmd, timeout)` | Run a shell command, streamed live; returns exit code + last 8 000 chars |
| `run_interactive(cmd, inputs)` | Drive `msfconsole`, `ssh`, `ftp`, `mysql`… through a pty (`pexpect`) |
| `read_file(path, max_bytes)` | Read a file (relative paths resolve inside `workspace/`) |
| `write_file(path, content, append)` | Write scripts / wordlists / notes |
| `list_dir(path)` | List a directory |
| `save_note(text, kind)` | Record a note or a **finding** (findings land in the report) |
| `set_scope(targets)` | Set authorised targets (IPs, CIDRs, domains, `*.wildcard`) — persisted |
| `ask_user(question)` | Pause and ask the human yes/no |
| `finish(summary, next_steps)` | End the task and export the Markdown report |
| `list_tool_categories()` | Categories with installed/available counts |
| `search_tools(query, category, limit)` | Search the full Kali catalog by keyword |
| `tool_help(name)` | Real `--help` / `-h` / `man` output (≤ 6 000 chars) |
| `install_tool(name)` | `apt-get install -y` with live output (passwordless sudo) |
| `refresh_tool_catalog()` | Rescan apt/dpkg + binary directories |

The full system prompt lives in `agent/system_prompt.py` and is passed verbatim as
`system_instruction`.

---

## 6. Safety

> **Uncensored mode** — on a disposable Kali Live system you can skip all of this with
> `--unsafe`. See [section 6b](#6b-uncensored--unsafe-mode-kali-live).

Two independent gates run before every command (`agent/safety.py`):

**a) Destructive-command blocklist** — regex rules plus a structural `rm` analysis:

* `rm -rf /`, `rm -rf ~`, `rm -rf /*`, recursive deletes inside `/etc`, `/boot`, `/usr`, `/var/log`…
* `mkfs*`, `dd … of=/dev/sdX`, `> /dev/sdX`, `wipefs`, `blkdiscard`, `shred … /dev/`
* fork bombs (`:(){ :|:& };:`)
* `chmod -R 777 /`, `chown -R … /`
* overwriting `/etc/passwd|shadow|sudoers|fstab|hosts|ssh/sshd_config`
* `shutdown` / `reboot` / `poweroff` / `systemctl reboot` / `init 0`
* `kill -9 1`, `history -c`, `journalctl --vacuum`, truncating `/var/log`
* `curl … | bash`, flushing firewall rules

**b) Scope enforcement** — every IP, CIDR and hostname found in a command is matched
against the active scope. Anything outside requires an explicit `yes`:

```
╭──────────────────────── approval needed ─────────────────────────╮
│ Scope: this command touches target(s) outside the active scope    │
│ (8.8.8.8; scope = 10.0.0.0/24).                                   │
│ Command: nmap -sV 8.8.8.8                                         │
│ Proceed anyway?                                                   │
╰───────────────────────────────────────────────────────────────────╯
```

**c) Repeat guard** — the tab keeps a short history of every command + exit code and refuses
to run an identical failing command a third time (or an identical successful one a sixth
time), telling the model to change approach instead of spinning.

With no human attached (no TTY / non-interactive) a risky command is **refused**, never
silently executed. Answers are logged (`user_answer`) so the audit trail is complete.

> The blocklist is defence-in-depth, **not** a sandbox. You remain responsible for the
> commands that run on your machine.

### 6b. Uncensored / unsafe mode (Kali Live)

If the machine is disposable (Kali Live USB, throwaway VM, lab range) you do not need the
confirmations. Enable unsafe mode once — it is stored in the config and stays on:

```bash
python main.py --unsafe          # aliases: --no-safety, --yolo
python main.py --safe            # turn the guards back on
```

In unsafe mode:

* destructive / irreversible commands (`rm -rf`, `mkfs`, `dd`, `wipefs`, `shutdown`, …)
  run immediately — no `ask_user` round-trip;
* the scope becomes **informational**: out-of-scope targets are used without asking;
* `sudo` is passwordless, so root work (including `sudo su -` style execution) just works;
* the system prompt is extended (`UNSAFE_ADDENDUM` in `agent/system_prompt.py`) so the model
  stops wasting steps on permission requests, but it still must not exfiltrate your
  files/keys to external services;
* **nothing is hidden**: every command that *would* have needed approval is still written to
  the JSONL log as `"event":"safety_bypassed"` with the matched rules and out-of-scope
  targets, so you can audit the session afterwards.

Toggle it live: `Ctrl+T` in the TUI, or type `unsafe on` / `unsafe off` in `--plain` /
`--tmux` mode. The status line shows `UNSAFE` while it is active.

```json
{"event":"safety_bypassed","command":"rm -rf /var/lib/foo","reasons":["recursive delete inside /var/lib can break the system"],"out_of_scope":[],"unsafe":true}
```

> There is **no** undo on a Live system either — the data you destroy in the live session is
> gone, and the guards are what stop a confused model from doing it by accident. Use
> `--unsafe` deliberately, not by default.

---

## 7. Logs, memory and reports

Every session writes an append-only JSONL file: `logs/20261101-211402.jsonl`

```json
{"ts":"2026-11-01T21:14:02.311+00:00","event":"session_start","model":"gemini-2.5-pro","scope":["10.10.10.0/24"],"mode":"tui"}
{"ts":"2026-11-01T21:14:07.884+00:00","event":"user_task","text":"enumerate SMB on 10.10.10.5"}
{"ts":"2026-11-01T21:14:09.002+00:00","event":"tool_call","name":"run_command","args":{"cmd":"nmap -sV -p445,139 10.10.10.5"}}
{"ts":"2026-11-01T21:14:21.447+00:00","event":"command","command":"nmap -sV -p445,139 10.10.10.5","exit_code":0,"duration_s":12.4,"output":"…full output…"}
{"ts":"2026-11-01T21:15:02.010+00:00","event":"note","kind":"finding","text":"445/tcp Windows Server 2019 (SMB signing off)"}
{"ts":"2026-11-01T21:15:40.000+00:00","event":"finish","summary":"…","report_path":"workspace/report-20261101-211540.md"}
```

Handy queries:

```bash
jq -r 'select(.event=="command") | "\(.exit_code)\t\(.duration_s)s\t\(.command)"' logs/*.jsonl
jq -r 'select(.event=="note" and .kind=="finding") | .text' logs/*.jsonl
jq -r 'select(.event=="safety_blocked") | .' logs/*.jsonl
jq -r 'select(.event=="safety_bypassed") | "\(.command)\t\(.reasons)"' logs/*.jsonl
```

* `agent/memory.py` keeps scope, notes, findings and the command timeline and exports a
  Markdown report (`## Findings`, command table, next steps) to
  `workspace/report-<timestamp>.md` when the model calls `finish`.
* On exit a `workspace/session-<id>.md` report is also written if anything happened.

---

## 8. Kali tool catalog

On first run KaliAgent scans the machine and caches the result in
`~/.config/kali-agent/tools_catalog.json`:

1. `apt-cache depends kali-linux-everything` → `kali-tools-*` metapackages → their dependency
   packages (the complete Kali toolset, installed or not),
2. `dpkg-query` → what is actually installed (and its short description),
3. `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/opt/*/bin` and `$PATH` → binaries, including
   locally installed tools.

Each entry gets `name, package, binary, installed, description, category, path`; the category
comes from `agent/kali_categories.py` (`recon`, `web`, `wireless`, `passwords`, `exploit`,
`sniff-spoof`, `forensics`, `reverse`, `post-exploit`, `reporting`, `misc`).

The catalog is reused for 7 days or until `--rescan` / `refresh_tool_catalog`.

---

## 9. Project layout

```
kali-agent/
├── main.py                    # entry point + CLI flags
├── requirements.txt
├── README.md
├── agent/
│   ├── __init__.py
│   ├── config.py              # first-run API key, save, reset (chmod 600)
│   ├── llm.py                 # Gemini client + manual function-calling loop
│   ├── system_prompt.py       # the agent's system prompt
│   ├── tools.py               # tool declarations + dispatch
│   ├── tool_registry.py       # Kali tool scan/search/help/install
│   ├── kali_categories.py     # category mapping
│   ├── executor.py            # command runner (live stream, timeout, sudo, pexpect)
│   ├── safety.py              # destructive filter + scope check
│   ├── memory.py              # session context + findings + Markdown report
│   └── logger.py              # logs/<session>.jsonl
├── ui/
│   ├── app.py                 # Textual TUI (+ rich console renderer)
│   └── tmux_bridge.py         # tmux live mode
├── logs/                      # one JSONL per session
├── workspace/                 # agent output: scripts, loot, reports
└── tests/
    ├── test_safety.py
    └── test_executor.py
```

### How a task flows

```
main.py → KaliAgent.send_task(task)
             │  chat.send_message(task)            (system prompt + 14 declarations)
             ▼
        resp.function_calls ──► ToolDispatcher.dispatch
             │                        │  safety.gate(cmd)          ← confirm / refuse
             │                        │  CommandExecutor.run        ← stream + log
             │                        ▼
             │                  function_response  ──► chat.send_message(parts)
             └──────────────► repeat until no function calls → final text
```

Ctrl+C kills the running process group and stops the loop; the log stays valid.

---

## 10. Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

* `tests/test_safety.py` — destructive patterns, target extraction, scope matching,
  approval/refusal flow (parameterised over ~60 commands).
* `tests/test_executor.py` — streaming, exit codes, stderr merge, timeout + process-group
  kill, cancellation, truncation, `cwd`, `pexpect` interaction.

Current state: **99 tests, all passing** (`python -m pytest tests/ -q`).

---

## 11. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `sudo: a password is required` | Set up passwordless sudo (section 3) |
| `No Gemini API key configured` | Run without `--non-interactive`, or `--reset-key` |
| `429 / quota` errors | Retried with exponential backoff; switch model with `--model gemini-2.5-flash` |
| Tool is missing | The agent calls `install_tool`; or `--rescan` after manual installs |
| `Textual is unavailable` | `pip install textual` (or keep using `--plain`) |
| tmux mode does nothing | `sudo apt install tmux`, then `tmux attach -t kali-agent` |
| A command hangs | It is killed at `--timeout` (default 180 s) |
| Too many approval prompts | Use `--unsafe` on a disposable system (section 6b) |
| Unsafe mode will not turn off | `python main.py --safe` (the flag is persisted in the config) |

---

## 12. Legal

KaliAgent is a tool for **authorised** security testing: your own systems, lab ranges
(HackTheBox, TryHackMe, VulnHub…), or engagements covered by written permission.
Running it against systems you do not own or have permission to test is illegal in most
jurisdictions. The scope guard exists to keep the agent honest — set it.
