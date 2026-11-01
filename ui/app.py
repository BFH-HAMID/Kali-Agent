"""User interfaces.

* :class:`KaliAgentApp` - the Textual TUI: chat/reasoning on the left, the live
  terminal on the right, command history at the bottom and a status line on top.
* :class:`ConsoleHooks` - a rich-powered plain console renderer used by
  ``--tmux`` / ``--plain`` mode (and by any non-TTY environment).

Both implement the same hooks interface that :class:`agent.llm.KaliAgent` and
:class:`agent.tools.ToolDispatcher` call into, so the agent code itself is
completely UI-agnostic.  All agent work happens in a Textual worker thread;
every callback is marshalled back with ``call_from_thread``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from agent.executor import CommandExecutor
from agent.llm import AgentHooks, KaliAgent
from agent.logger import SessionLogger
from agent.memory import Memory
from agent.safety import SafetyGuard
from agent.tool_registry import ToolRegistry
from agent.tools import ToolContext, ToolDispatcher

# --------------------------------------------------------------------------
# Textual is optional at import time so plain mode works without it installed
# --------------------------------------------------------------------------
try:  # pragma: no cover - exercised by the TUI
    from textual import work
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import DataTable, Footer, Header, Input, RichLog, Static

    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover
    TEXTUAL_AVAILABLE = False
    App = object  # type: ignore[assignment,misc]
    ComposeResult = object  # type: ignore[assignment,misc]

    def work(*_args: Any, **_kwargs: Any):  # type: ignore[misc]
        """No-op stand-in for textual.work when Textual is missing."""

        def decorator(func):
            return func

        return decorator


# --------------------------------------------------------------------------
# plain console renderer
# --------------------------------------------------------------------------


class ConsoleHooks(AgentHooks):
    """Render agent activity on a normal terminal (used by --plain/--tmux)."""

    def __init__(self, console: Console | None = None, show_output: bool = True) -> None:
        self.console = console or Console()
        self.show_output = show_output

    # ------------------------------------------------------------ callbacks
    def on_status(self, text: str) -> None:
        self.console.print(Text(f"· {text}", style="dim"))

    def on_assistant_text(self, text: str) -> None:
        if not text.strip():
            return
        self.console.print()
        self.console.print(Panel(Markdown(text), border_style="cyan", title="agent"))

    def on_tool_call(self, name: str, args: dict[str, Any]) -> None:
        self.console.print(Text(f"→ {name} {_summarise_args(args)}", style="bold cyan"))

    def on_output(self, line: str) -> None:
        if not self.show_output:
            return
        self.console.print(Text(line, style="dim"))

    def on_command_result(
        self, command: str, exit_code: int, duration: float, timed_out: bool
    ) -> None:
        style = "green" if exit_code == 0 else "red"
        label = "timeout" if timed_out else f"exit {exit_code}"
        self.console.print(Text(f"  └─ {label} in {duration:.1f}s", style=style))

    def on_scope(self, scope: list[str]) -> None:
        label = ", ".join(scope) if scope else "unrestricted"
        self.console.print(Text(f"scope set: {label}", style="bold magenta"))

    def ask_user(self, question: str, kind: str = "yesno") -> bool:
        self.console.print()
        self.console.print(Panel(question, border_style="yellow", title="approval needed"))
        try:
            answer = Prompt.ask(
                "[bold yellow]Approve?[/]",
                choices=["y", "n"],
                default="n",
                console=self.console,
            )
        except (EOFError, KeyboardInterrupt):
            self.console.print(Text("no answer - refusing.", style="red"))
            return False
        return answer.strip().lower() in {"y", "yes"}


def _summarise_args(args: dict[str, Any], limit: int = 140) -> str:
    parts: list[str] = []
    for key, value in args.items():
        text = str(value).replace("\n", " ")
        if len(text) > 60:
            text = text[:57] + "..."
        parts.append(f"{key}={text}")
    joined = ", ".join(parts)
    if len(joined) > limit:
        joined = joined[: limit - 3] + "..."
    return f"({joined})"


# --------------------------------------------------------------------------
# Textual TUI
# --------------------------------------------------------------------------


@dataclass
class AppSession:
    """Runtime objects shared between ``main.py`` and the TUI."""

    api_key: str
    model: str
    registry: ToolRegistry
    executor: CommandExecutor
    safety: SafetyGuard
    memory: Memory
    logger: SessionLogger
    workspace: Path
    root: Path
    allow_install: bool = True
    max_steps: int = 40


class KaliAgentApp(App):
    """The live Textual UI for KaliAgent."""

    CSS = """
    Screen { layout: vertical; }
    #status {
        dock: top;
        height: 1;
        padding: 0 1;
        background: $panel;
        color: cyan;
    }
    #panes { height: 1fr; }
    #chat-pane { width: 3fr; border: round cyan; }
    #term-pane { width: 2fr; border: round magenta; }
    .pane-title {
        height: 1;
        padding: 0 1;
        background: $boost;
        color: yellow;
    }
    #chat, #term { height: 1fr; padding: 0 1; }
    #history-title { height: 1; padding: 0 1; background: $boost; color: yellow; }
    #history { height: 7; border: round green; }
    #prompt { height: 3; }
    """

    #: Ctrl+C stays free (browser/terminal copy); Ctrl+Q quits.
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("escape", "cancel_task", "Stop task"),
        ("ctrl+l", "clear_terminal", "Clear terminal"),
        ("ctrl+r", "rescan_tools", "Rescan tools"),
        ("ctrl+n", "new_chat", "New chat"),
    ]

    def __init__(self, session: AppSession, initial_task: str | None = None) -> None:
        super().__init__()
        self.session = session
        self.initial_task = initial_task

        self._agent: KaliAgent | None = None
        self._busy = False
        self._status_note = "ready"
        self._history: list[tuple[str, str, str, str]] = []

        self._question_event: threading.Event | None = None
        self._question_answer: dict[str, bool] = {}
        self._cancel_requested = False

    # ------------------------------------------------------------- lifecycle
    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield Header(show_clock=True)
        yield Static(self._status_text(), id="status")
        with Horizontal(id="panes"):
            with Vertical(id="chat-pane"):
                yield Static("Agent · reasoning & answers", classes="pane-title")
                yield RichLog(id="chat", wrap=True, markup=False, auto_scroll=True)
            with Vertical(id="term-pane"):
                yield Static("Live terminal", classes="pane-title")
                yield RichLog(
                    id="term", wrap=False, markup=False, auto_scroll=True, max_lines=5000
                )
        yield Static(
            "Command history  ·  Esc stop · Ctrl+R rescan · Ctrl+N new chat",
            id="history-title",
        )
        yield DataTable(id="history")
        yield Input(
            placeholder="Describe the task, e.g. 'scan 10.0.0.0/24 with nmap'", id="prompt"
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Time", "Exit", "Duration", "Command")
        table.cursor_type = "row"

        # the executor streams lines from its worker thread -> marshal to the UI
        self.session.executor.on_line = self.on_output
        self.query_one("#prompt", Input).focus()
        self.set_interval(1.0, self._refresh_status)

        self._write_chat_note(
            "KaliAgent ready - every command runs on this machine, live, and the "
            "safety layer enforces the scope."
        )
        if self.initial_task:
            self._start_task(self.initial_task)

    def on_unmount(self) -> None:
        # release a blocked agent thread, stop any command and close the log
        if self._question_event is not None and not self._question_event.is_set():
            self._question_answer["value"] = False
            self._question_event.set()
        try:
            self.session.executor.cancel()
        except Exception:
            pass
        self.session.logger.session_end("tui-exit")
        self.session.logger.close()

    # ---------------------------------------------------------------- agent
    def _ensure_agent(self) -> KaliAgent:
        if self._agent is None:
            dispatcher = ToolDispatcher(
                ToolContext(
                    executor=self.session.executor,
                    registry=self.session.registry,
                    safety=self.session.safety,
                    memory=self.session.memory,
                    logger=self.session.logger,
                    hooks=self,  # type: ignore[arg-type]
                    workspace=self.session.workspace,
                    root=self.session.root,
                    allow_install=self.session.allow_install,
                )
            )
            self._agent = KaliAgent(
                api_key=self.session.api_key,
                model=self.session.model,
                dispatcher=dispatcher,
                hooks=self,  # type: ignore[arg-type]
                logger=self.session.logger,
                memory=self.session.memory,
                max_steps=self.session.max_steps,
            )
        return self._agent

    # ------------------------------------------------------------ hook layer
    def _ui(self, fn, *args: Any) -> None:
        """Call ``fn`` in the UI thread, from any thread."""

        if threading.current_thread() is threading.main_thread():
            try:
                fn(*args)
            except Exception:  # pragma: no cover - UI must not break the agent
                pass
            return
        try:
            self.call_from_thread(fn, *args)
        except Exception:  # pragma: no cover - app shutting down
            pass

    def on_status(self, text: str) -> None:
        self._ui(self._set_note, text)

    def on_assistant_text(self, text: str) -> None:
        self._ui(self._write_chat_agent, text)

    def on_tool_call(self, name: str, args: dict[str, Any]) -> None:
        # Esc pressed while the agent was thinking/working: abort before the
        # next tool runs. Raising KeyboardInterrupt here is caught by the agent
        # loop, which cancels the running command and stops cleanly.
        if self._cancel_requested:
            raise KeyboardInterrupt
        self._ui(self._write_chat_tool, name, _summarise_args(args))

    def on_output(self, line: str) -> None:
        self._ui(self._write_term, line)

    def on_command_result(
        self, command: str, exit_code: int, duration: float, timed_out: bool
    ) -> None:
        self._ui(self._add_history, command, exit_code, duration, timed_out)

    def on_scope(self, scope: list[str]) -> None:
        self._ui(self._scope_changed, scope)

    def ask_user(self, question: str, kind: str = "yesno") -> bool:
        """Block the agent thread until the user answers in the input box."""

        event = threading.Event()
        self._question_answer = {}
        self._question_event = event
        self._ui(self._begin_question, question)
        answered = event.wait(timeout=900)
        self._question_event = None
        if not answered:
            self._ui(self._write_chat_note, "no answer within 15 minutes - treating as NO")
            self._ui(self._reset_prompt)
            return False
        self._ui(self._reset_prompt)
        return bool(self._question_answer.get("value", False))

    # ------------------------------------------------------------- UI writes
    def _chat_log(self) -> RichLog:
        return self.query_one("#chat", RichLog)

    def _term_log(self) -> RichLog:
        return self.query_one("#term", RichLog)

    def _write_chat_agent(self, text: str) -> None:
        log = self._chat_log()
        log.write(Text("agent", style="bold cyan"))
        for line in (text.splitlines() or [""]):
            log.write(Text(f"  {line}", style="white"))
        log.write(Text(""))

    def _write_chat_tool(self, name: str, summary: str) -> None:
        self._chat_log().write(Text(f"→ {name} {summary}", style="cyan"))

    def _write_chat_note(self, text: str, style: str = "yellow") -> None:
        self._chat_log().write(Text(f"• {text}", style=style))

    def _write_term(self, line: str) -> None:
        if line.startswith("$ "):
            self._term_log().write(Text(line, style="bold green"))
        elif line.startswith("["):
            self._term_log().write(Text(line, style="yellow"))
        else:
            self._term_log().write(Text(line, style="grey70"))

    def _add_history(
        self, command: str, exit_code: int, duration: float, timed_out: bool
    ) -> None:
        stamp = time.strftime("%H:%M:%S")
        exit_text = "timeout" if timed_out else str(exit_code)
        short = command.replace("\n", " ")
        if len(short) > 70:
            short = short[:67] + "..."
        self._history.append((stamp, exit_text, f"{duration:.1f}s", short))
        if len(self._history) > 250:
            self._history = self._history[-200:]
        table = self.query_one(DataTable)
        table.clear()
        for row in self._history:
            table.add_row(*row)

    def _scope_changed(self, scope: list[str]) -> None:
        self._write_chat_note(
            "scope: " + (", ".join(scope) if scope else "unrestricted"), style="magenta"
        )
        self._refresh_status()

    def _set_note(self, text: str) -> None:
        self._status_note = text
        self._refresh_status()

    def _status_text(self) -> str:
        installed, total = self.session.registry.counts()
        scope = ", ".join(self.session.memory.scope) or "unrestricted"
        return (
            f"Tools: {installed} installed / {total} available | Scope: {scope} | "
            f"{self.session.model} | {self._status_note}"
        )

    def _refresh_status(self) -> None:
        try:
            self.query_one("#status", Static).update(self._status_text())
        except Exception:  # pragma: no cover - during shutdown
            pass

    # ------------------------------------------------------------- questions
    def _begin_question(self, question: str) -> None:
        self._write_chat_note(question, style="bold yellow")
        self._write_chat_note("answer below: y = approve, n = refuse", style="yellow")
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "y / n then Enter"
        prompt.focus()

    def _reset_prompt(self) -> None:
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "Describe the task, e.g. 'scan 10.0.0.0/24 with nmap'"
        prompt.focus()

    def _answer_question(self, text: str) -> None:
        answer = text.strip().lower()
        approved: bool | None = None
        if answer in {"y", "yes", "ok", "approve", "ha", "haan", "হ্যাঁ", "1", "true"}:
            approved = True
        elif answer in {"n", "no", "refuse", "na", "cancel", "না", "0", "false"}:
            approved = False
        if approved is None:
            self._write_chat_note("please answer y or n", style="red")
            return
        event = self._question_event
        if event is not None:
            self._question_answer["value"] = approved
            event.set()

    # ---------------------------------------------------------------- tasks
    def _start_task(self, task: str) -> None:
        if self._busy:
            self._write_chat_note("still working - press Esc to stop first", style="red")
            return
        self._busy = True
        self._cancel_requested = False
        self._write_chat_note(f"task: {task}", style="bold white")
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "working… press Esc to stop"
        self._set_note("thinking...")
        self._task_worker(task)

    @work(thread=True, exclusive=True, group="agent")
    def _task_worker(self, task: str) -> None:
        """Run the agent loop in a background thread."""

        try:
            agent = self._ensure_agent()
            agent.send_task(task)
        except Exception as exc:  # pragma: no cover - defensive
            self.session.logger.error(f"tui task error: {exc}")
            self._ui(self._write_chat_note, f"error: {exc}", "red")
        finally:
            self._ui(self._task_finished)

    def _task_finished(self) -> None:
        self._busy = False
        self._cancel_requested = False
        self._reset_prompt()
        self._set_note("ready")

    # -------------------------------------------------------------- actions
    def action_cancel_task(self) -> None:
        if self._question_event is not None and not self._question_event.is_set():
            self._question_answer["value"] = False
            self._question_event.set()
            self._write_chat_note("question cancelled", style="red")
            return
        if self._busy:
            self._cancel_requested = True
            self._write_chat_note(
                "stopping: killing the running command and ending the task...", style="red"
            )
            try:
                self.session.executor.cancel()
            except Exception:
                pass
            self._set_note("stopping...")

    def action_clear_terminal(self) -> None:
        try:
            self._term_log().clear()
        except Exception:
            pass

    def action_new_chat(self) -> None:
        if self._agent is not None:
            self._agent.reset()
        self._write_chat_note(
            "conversation reset (scope and notes are kept)", style="yellow"
        )

    def action_rescan_tools(self) -> None:
        if self._busy:
            self._write_chat_note("finish the current task first", style="red")
            return
        self._set_note("rescanning tool catalog...")
        self._rescan_worker()

    @work(thread=True, group="rescan", exclusive=True)
    def _rescan_worker(self) -> None:
        try:
            stats = self.session.registry.scan(on_status=self.on_status)
            self.on_status(
                f"catalog: {stats['installed']} installed / {stats['available']} available"
            )
        except Exception as exc:  # pragma: no cover
            self.on_status(f"rescan failed: {exc}")

    # ---------------------------------------------------------------- input
    def on_input_submitted(self, event: Any) -> None:
        text = (event.value or "").strip()
        event.input.value = ""

        if self._question_event is not None and not self._question_event.is_set():
            self._answer_question(text)
            return

        if not text:
            return
        if text.lower() in {"quit", "exit", ":q"}:
            self.exit()
            return
        self._start_task(text)


__all__ = ["AppSession", "ConsoleHooks", "KaliAgentApp", "TEXTUAL_AVAILABLE"]
