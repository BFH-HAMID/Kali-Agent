"""Tools exposed to Gemini: JSON-schema declarations + the dispatch table.

The model never touches the shell directly.  Every function call lands in
:meth:`ToolDispatcher.dispatch`, which:

1. runs the safety gate (:class:`agent.safety.SafetyGuard`) where relevant,
2. executes the action,
3. records it in memory + the JSONL log,
4. returns a compact JSON-able result for the model.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from google.genai import types

from .config import load_config, save_config
from .executor import CommandExecutor, ExecResult
from .logger import SessionLogger
from .memory import Memory
from .safety import SafetyGuard
from .tool_registry import ToolRegistry

S = types.Schema
T = types.Type

#: Output of ``read_file`` / ``write_file`` is capped so one call cannot blow up
#: the model's context window.
MAX_READ_CHARS = 120_000

#: Maximum timeout a single ``run_command`` may request (seconds).
MAX_TIMEOUT = 3600.0


class AgentFinished(Exception):
    """Raised by the ``finish`` tool to end the agent loop."""

    def __init__(
        self,
        summary: str,
        next_steps: Sequence[str] | None = None,
        report_path: str | None = None,
    ) -> None:
        super().__init__(summary)
        self.summary = summary
        self.next_steps = [s for s in (next_steps or []) if s]
        self.report_path = report_path


class ToolHooks(Protocol):
    """The subset of UI callbacks the dispatcher needs."""

    def on_status(self, text: str) -> None: ...

    def on_scope(self, scope: list[str]) -> None: ...

    def on_command_result(
        self, command: str, exit_code: int, duration: float, timed_out: bool
    ) -> None: ...

    def ask_user(self, question: str, kind: str = "yesno") -> bool: ...


# --------------------------------------------------------------------------
# declaration helpers
# --------------------------------------------------------------------------
def _obj(properties: dict[str, Any], required: Sequence[str] = ()) -> Any:
    return S(type=T.OBJECT, properties=properties, required=list(required))


def _str(description: str, enum: Sequence[str] | None = None) -> Any:
    if enum:
        return S(type=T.STRING, description=description, enum=list(enum))
    return S(type=T.STRING, description=description)


def _int(description: str) -> Any:
    return S(type=T.INTEGER, description=description)


def _bool(description: str) -> Any:
    return S(type=T.BOOLEAN, description=description)


def _arr(description: str, item: Any) -> Any:
    return S(type=T.ARRAY, description=description, items=item)


def build_declarations() -> list[Any]:
    """All function declarations handed to Gemini."""

    return [
        types.FunctionDeclaration(
            name="run_command",
            description=(
                "Run a shell command on the Kali machine and return its exit code and "
                "output (the last ~8000 chars). Output streams live to the user. "
                "Use non-interactive flags; redirect large output to ./workspace and "
                "inspect it with grep/head/awk. sudo is available without a password."
            ),
            parameters=_obj(
                {
                    "cmd": _str("The shell command to execute (bash syntax)."),
                    "timeout": _int(
                        "Seconds before the command is killed (default 180, max 3600)."
                    ),
                },
                ["cmd"],
            ),
        ),
        types.FunctionDeclaration(
            name="run_interactive",
            description=(
                "Drive an interactive program through a pseudo-terminal (msfconsole, "
                "ssh, ftp, nc, mysql, impacket scripts). Provide the exact lines to "
                "type whenever the program waits for input. Output streams live."
            ),
            parameters=_obj(
                {
                    "cmd": _str("Command that starts the interactive program."),
                    "inputs": _arr(
                        "Lines to send, in order, each time the program waits for input.",
                        S(type=T.STRING),
                    ),
                    "timeout": _int("Overall timeout in seconds (default 300)."),
                },
                ["cmd", "inputs"],
            ),
        ),
        types.FunctionDeclaration(
            name="read_file",
            description=(
                "Read a text file. Relative paths resolve inside the project's "
                "workspace/ directory."
            ),
            parameters=_obj(
                {
                    "path": _str("File to read (absolute, or relative to workspace/)."),
                    "max_bytes": _int("Maximum characters to return (default 20000)."),
                },
                ["path"],
            ),
        ),
        types.FunctionDeclaration(
            name="write_file",
            description=(
                "Create or overwrite a text file (scripts, payload lists, notes). "
                "Relative paths resolve inside workspace/."
            ),
            parameters=_obj(
                {
                    "path": _str("Destination path."),
                    "content": _str("Text content to write."),
                    "append": _bool("Append instead of overwriting (default false)."),
                },
                ["path", "content"],
            ),
        ),
        types.FunctionDeclaration(
            name="list_dir",
            description="List files in a directory (default: the workspace/ folder).",
            parameters=_obj({"path": _str("Directory to list.")}),
        ),
        types.FunctionDeclaration(
            name="save_note",
            description=(
                "Record a note or a finding (open port, version, vulnerability, "
                "credential, file path). Findings end up in the Markdown report."
            ),
            parameters=_obj(
                {
                    "text": _str("The note/finding text."),
                    "kind": _str(
                        "Either 'note' or 'finding'.", ["note", "finding"]
                    ),
                },
                ["text"],
            ),
        ),
        types.FunctionDeclaration(
            name="set_scope",
            description=(
                "Set the authorised targets for this session (IPs, CIDR blocks, "
                "domains, *.wildcards). Commands touching anything outside the scope "
                "need explicit human approval."
            ),
            parameters=_obj(
                {
                    "targets": _arr(
                        "Scope entries, e.g. ['10.0.0.0/24', 'example.com'].",
                        S(type=T.STRING),
                    )
                },
                ["targets"],
            ),
        ),
        types.FunctionDeclaration(
            name="ask_user",
            description=(
                "Ask the human a yes/no question and wait for the answer. Use for "
                "destructive actions, out-of-scope targets, or a decision only the "
                "user can make. Returns {'approved': true/false}."
            ),
            parameters=_obj({"question": _str("The question to ask.")}, ["question"]),
        ),
        types.FunctionDeclaration(
            name="finish",
            description=(
                "End the task. Provide what was done, the key findings, and the "
                "suggested next steps. Call this once the objective is met."
            ),
            parameters=_obj(
                {
                    "summary": _str(
                        "Markdown summary: what was done, findings, commands used."
                    ),
                    "next_steps": _arr(
                        "Suggested next steps.", S(type=T.STRING)
                    ),
                },
                ["summary"],
            ),
        ),
        types.FunctionDeclaration(
            name="list_tool_categories",
            description=(
                "List the Kali tool categories with how many tools are installed / "
                "available in each, plus the current scope."
            ),
        ),
        types.FunctionDeclaration(
            name="search_tools",
            description=(
                "Search the full Kali catalog (installed and installable) by keyword. "
                "Use this before guessing a tool name."
            ),
            parameters=_obj(
                {
                    "query": _str("Keyword, e.g. 'sql injection', 'wifi', 'smb'."),
                    "category": _str(
                        "Optional category filter.",
                        [
                            "recon",
                            "web",
                            "wireless",
                            "passwords",
                            "exploit",
                            "sniff-spoof",
                            "forensics",
                            "reverse",
                            "post-exploit",
                            "reporting",
                            "misc",
                        ],
                    ),
                    "limit": _int("Maximum results (default 15)."),
                    "installed_only": _bool("Only show installed tools."),
                },
                ["query"],
            ),
        ),
        types.FunctionDeclaration(
            name="tool_help",
            description=(
                "Return the real --help / -h / man output of a tool (max 6000 chars). "
                "Always call this instead of guessing syntax."
            ),
            parameters=_obj({"name": _str("Tool or package name.")}, ["name"]),
        ),
        types.FunctionDeclaration(
            name="install_tool",
            description=(
                "Install a missing Kali package with apt-get (passwordless sudo). "
                "Output streams live."
            ),
            parameters=_obj({"name": _str("Package name to install.")}, ["name"]),
        ),
        types.FunctionDeclaration(
            name="refresh_tool_catalog",
            description=(
                "Rescan apt/dpkg and the binary directories to rebuild the tool "
                "catalog (do this after installing packages outside apt)."
            ),
        ),
    ]


# --------------------------------------------------------------------------
# dispatcher
# --------------------------------------------------------------------------
@dataclass
class ToolContext:
    """Everything a tool handler may need."""

    executor: CommandExecutor
    registry: ToolRegistry
    safety: SafetyGuard
    memory: Memory
    logger: SessionLogger
    hooks: ToolHooks
    workspace: Path
    root: Path
    allow_install: bool = True


class ToolDispatcher:
    """Execute function calls coming from Gemini."""

    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.declarations = build_declarations()
        #: command -> list of exit codes, used to stop retry loops
        self._cmd_history: dict[str, list[int]] = {}

    def new_task(self) -> None:
        """Reset per-task state (called by the agent loop for every task)."""

        self._cmd_history.clear()

    def _repeat_guard(self, cmd: str) -> dict[str, Any] | None:
        """Refuse to run the same command a third time with the same result.

        The system prompt forbids repeating an identical failing command more
        than twice; this enforces it so a confused model cannot spin.
        """

        runs = self._cmd_history.get(cmd)
        if not runs:
            return None
        last = runs[-1]
        # two identical failures, or five identical successes, are enough
        limit = 2 if last != 0 else 5
        if runs.count(last) < limit:
            return None
        return {
            "error": (
                f"this exact command already ran {runs.count(last)}x and returned "
                f"exit code {last}; it is not being run again."
            ),
            "command": cmd,
            "hint": (
                "Change approach: different flags or tool (search_tools/tool_help), "
                "inspect the output you already have, or ask the user."
            ),
            "repeated": True,
        }

    # ------------------------------------------------------------- plumbing
    def _resolve(self, path: str) -> Path:
        raw = (path or ".").strip() or "."
        expanded = Path(raw).expanduser()
        if not expanded.is_absolute():
            expanded = self.ctx.workspace / expanded
        return expanded

    def _log_tool(self, name: str, args: dict[str, Any]) -> None:
        self.ctx.logger.tool_call(name, args)

    def dispatch(self, name: str, args: dict[str, Any] | None) -> dict[str, Any]:
        """Route one function call and always return a JSON-able dict."""

        args = dict(args or {})
        self._log_tool(name, args)
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return {"error": f"unknown tool '{name}'"}

        try:
            result = handler(args)
        except AgentFinished:
            raise
        except Exception as exc:  # never let a tool crash the loop
            self.ctx.logger.error(f"{name} failed: {exc}", tool=name)
            return {"error": f"{name} failed: {exc}"}

        try:
            json.dumps(result, default=str)
        except (TypeError, ValueError):
            result = {"result": str(result)}
        self.ctx.logger.tool_result(name, _shrink(result))
        return result

    # ----------------------------------------------------------- commands
    def _run(
        self, cmd: str, timeout: float | None, interactive: bool, inputs: Any
    ) -> dict[str, Any]:
        result: ExecResult
        if interactive:
            result = self.ctx.executor.run_interactive(cmd, inputs, timeout=timeout)
        else:
            result = self.ctx.executor.run(cmd, timeout=timeout)
        history = self._cmd_history.setdefault(cmd, [])
        history.append(result.exit_code)
        self.ctx.memory.add_command(result)
        self.ctx.logger.command(
            result, tool="run_interactive" if interactive else "run_command"
        )
        try:
            self.ctx.hooks.on_command_result(
                cmd, result.exit_code, result.duration, result.timed_out
            )
        except Exception:
            pass
        return result.to_tool_response()

    def _gate(self, cmd: str) -> dict[str, Any] | None:
        """Run the safety gate; return an error payload when command is refused."""

        decision = self.ctx.safety.gate(cmd)
        if decision.allowed:
            if decision.reasons or decision.out_of_scope:
                self.ctx.logger.log(
                    "safety_approved",
                    command=cmd,
                    reasons=decision.reasons,
                    out_of_scope=decision.out_of_scope,
                )
            return None

        self.ctx.logger.log(
            "safety_blocked",
            command=cmd,
            reason=decision.denied_reason or decision.describe(),
        )
        try:
            self.ctx.hooks.on_status(f"refused: {decision.denied_reason}")
        except Exception:
            pass
        return {
            "error": "command refused by the safety layer: "
            + (decision.denied_reason or decision.describe()),
            "command": cmd,
            "hint": (
                "Do not retry the same command. Explain the risk to the user, or "
                "choose a non-destructive alternative inside the scope."
            ),
        }

    def _tool_run_command(self, args: dict[str, Any]) -> dict[str, Any]:
        cmd = str(args.get("cmd") or args.get("command") or "").strip()
        if not cmd:
            return {"error": "cmd is required"}
        timeout = _coerce_timeout(args.get("timeout"))
        repeated = self._repeat_guard(cmd)
        if repeated is not None:
            self.ctx.logger.log("repeat_blocked", command=cmd)
            return repeated
        blocked = self._gate(cmd)
        if blocked is not None:
            return blocked
        return self._run(cmd, timeout, interactive=False, inputs=None)

    def _tool_run_interactive(self, args: dict[str, Any]) -> dict[str, Any]:
        cmd = str(args.get("cmd") or "").strip()
        if not cmd:
            return {"error": "cmd is required"}
        inputs = args.get("inputs") or []
        if isinstance(inputs, str):
            inputs = [inputs]
        inputs = [str(i) for i in inputs]
        timeout = _coerce_timeout(args.get("timeout"), default=300.0)
        repeated = self._repeat_guard(cmd)
        if repeated is not None:
            self.ctx.logger.log("repeat_blocked", command=cmd)
            return repeated
        blocked = self._gate(cmd)
        if blocked is not None:
            return blocked
        return self._run(cmd, timeout, interactive=True, inputs=inputs)

    # -------------------------------------------------------------- files
    def _tool_read_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(str(args.get("path") or ""))
        if not path.exists():
            return {"error": f"no such file: {path}"}
        if path.is_dir():
            return {"error": f"{path} is a directory - use list_dir"}
        limit = int(args.get("max_bytes") or 20_000)
        limit = max(200, min(limit, MAX_READ_CHARS))
        try:
            data = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"error": f"cannot read {path}: {exc}"}
        truncated = len(data) > limit
        return {
            "path": str(path),
            "content": data[:limit],
            "bytes": len(data.encode("utf-8", "ignore")),
            "truncated": truncated,
        }

    def _tool_write_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(str(args.get("path") or ""))
        content = str(args.get("content") or "")
        append = bool(args.get("append"))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a" if append else "w", encoding="utf-8") as handle:
                handle.write(content)
        except OSError as exc:
            return {"error": f"cannot write {path}: {exc}"}
        self.ctx.logger.log(
            "file_write", path=str(path), chars=len(content), append=append
        )
        return {
            "path": str(path),
            "chars_written": len(content),
            "mode": "append" if append else "overwrite",
        }

    def _tool_list_dir(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve(str(args.get("path") or "."))
        if not path.exists():
            return {"error": f"no such directory: {path}"}
        if not path.is_dir():
            return {"error": f"{path} is not a directory"}
        entries: list[dict[str, Any]] = []
        try:
            for item in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name)):
                try:
                    stat = item.stat()
                except OSError:
                    continue
                entries.append(
                    {
                        "name": item.name,
                        "type": "dir" if item.is_dir() else "file",
                        "size": stat.st_size,
                    }
                )
        except OSError as exc:
            return {"error": f"cannot list {path}: {exc}"}
        return {"path": str(path), "count": len(entries), "entries": entries[:400]}

    # -------------------------------------------------------------- notes
    def _tool_save_note(self, args: dict[str, Any]) -> dict[str, Any]:
        text = str(args.get("text") or "").strip()
        if not text:
            return {"error": "text is required"}
        kind = str(args.get("kind") or "note").lower()
        if kind not in {"note", "finding"}:
            kind = "note"
        note = self.ctx.memory.add_note(text, kind)
        self.ctx.logger.note(text, kind)
        try:
            self.ctx.hooks.on_status(f"saved {kind}")
        except Exception:
            pass
        return {"saved": kind, "at": note.created_at, "notes_total": len(self.ctx.memory.notes)}

    def _tool_set_scope(self, args: dict[str, Any]) -> dict[str, Any]:
        raw = args.get("targets")
        if isinstance(raw, str):
            raw = [t for t in raw.replace(",", " ").split() if t]
        if not isinstance(raw, list) or not raw:
            return {"error": "targets must be a non-empty list"}
        targets = [str(t).strip() for t in raw if str(t).strip()]
        scope = self.ctx.memory.set_scope(targets)
        self.ctx.safety.set_scope(scope)
        self.ctx.logger.scope(scope)
        try:
            self.ctx.hooks.on_scope(scope)
        except Exception:
            pass
        # persist so the next session starts with the same scope
        try:
            config = load_config()
            if config is not None:
                config.scope = scope
                save_config(config)
        except Exception:
            pass
        return {"scope": scope, "count": len(scope)}

    def _tool_ask_user(self, args: dict[str, Any]) -> dict[str, Any]:
        question = str(args.get("question") or "").strip()
        if not question:
            return {"error": "question is required"}
        approved = bool(self.ctx.hooks.ask_user(question))
        self.ctx.logger.answer(question, approved)
        return {
            "approved": approved,
            "answer": "yes" if approved else "no",
            "guidance": (
                "The user approved - continue."
                if approved
                else "The user declined. Do not perform that action; propose an alternative."
            ),
        }

    def _tool_finish(self, args: dict[str, Any]) -> dict[str, Any]:
        summary = str(args.get("summary") or "").strip() or "(no summary provided)"
        next_steps = args.get("next_steps") or []
        if isinstance(next_steps, str):
            next_steps = [next_steps]
        next_steps = [str(s) for s in next_steps if str(s).strip()]

        self.ctx.memory.set_finish(summary, next_steps)
        report_path = ""
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            report = self.ctx.workspace / f"report-{stamp}.md"
            report.parent.mkdir(parents=True, exist_ok=True)
            self.ctx.memory.export(report)
            report_path = str(report)
        except OSError as exc:  # pragma: no cover
            self.ctx.logger.error(f"could not export report: {exc}")

        self.ctx.logger.finish(summary, report_path or None)
        raise AgentFinished(summary, next_steps, report_path or None)

    # ---------------------------------------------------------- discovery
    def _tool_list_tool_categories(self, args: dict[str, Any]) -> dict[str, Any]:
        stats = self.ctx.registry.stats()
        return {
            "categories": self.ctx.registry.categories(),
            "installed": stats["installed"],
            "available": stats["available"],
            "scope": self.ctx.memory.scope or "unrestricted",
            "catalog_generated_at": stats["generated_at"],
        }

    def _tool_search_tools(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query") or "").strip()
        if not query:
            return {"error": "query is required"}
        category = args.get("category")
        if category is not None:
            category = str(category).strip().lower() or None
        limit = int(args.get("limit") or 15)
        limit = max(1, min(limit, 50))
        results = self.ctx.registry.search(
            query,
            limit=limit,
            category=category,
            installed_only=bool(args.get("installed_only")),
        )
        return {
            "query": query,
            "count": len(results),
            "results": [entry.as_payload() for entry in results],
            "total_in_catalog": self.ctx.registry.stats()["available"],
        }

    def _tool_tool_help(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args.get("name") or "").strip()
        if not name:
            return {"error": "name is required"}
        return self.ctx.registry.help_text(name)

    def _tool_install_tool(self, args: dict[str, Any]) -> dict[str, Any]:
        name = str(args.get("name") or "").strip()
        if not name:
            return {"error": "name is required"}
        if not self.ctx.allow_install:
            return {"error": "tool installation is disabled for this session"}
        try:
            self.ctx.hooks.on_status(f"installing {name} ...")
        except Exception:
            pass
        result = self.ctx.registry.install(name)
        self.ctx.logger.log("install", name=name, result=_shrink(result))
        return result

    def _tool_refresh_tool_catalog(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            stats = self.ctx.registry.scan(on_status=self.ctx.hooks.on_status)
        except Exception as exc:
            return {"error": f"rescan failed: {exc}"}
        return {"status": "rescanned", **stats}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _coerce_timeout(value: Any, default: float = 180.0) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return default
    if timeout <= 0:
        return default
    return min(timeout, MAX_TIMEOUT)


def _shrink(payload: Any, limit: int = 4000) -> Any:
    """Trim large payloads before they reach the log."""

    try:
        text = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        return str(payload)[:limit]
    if len(text) <= limit:
        return payload
    return {"truncated": True, "preview": text[:limit]}


def quote(value: str) -> str:
    """Shell-quote a value (used by tool handlers that build commands)."""

    return shlex.quote(value)


__all__ = [
    "AgentFinished",
    "MAX_READ_CHARS",
    "ToolContext",
    "ToolDispatcher",
    "ToolHooks",
    "build_declarations",
    "quote",
]
