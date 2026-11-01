#!/usr/bin/env python3
"""KaliAgent - an autonomous AI operator for Kali Linux.

Entry point and CLI.

Examples
--------
    python main.py                                  # Textual TUI
    python main.py "enumerate 10.10.10.0/24"        # TUI with an initial task
    python main.py --tmux                           # commands run in tmux
    python main.py --plain --scope 10.10.10.0/24    # console mode, scoped
    python main.py --rescan --model gemini-2.5-flash
    python main.py --reset-key
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS_DIR = ROOT / "logs"
WORKSPACE_DIR = ROOT / "workspace"

BANNER = r"""
 _  __     _ _    _                 _
| |/ /__ _| (_)  / \   __ _  ___ _ __ | |_
| ' </ _` | | | / _ \ / _` |/ _ \ '_ \| __|
|_|\_\__,_|_|_|/_/ \_\\__, |\___/| | | |_
                      |___/     |_| |_|\_|  autonomous Kali operator
""".strip("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kali-agent",
        description=(
            "Autonomous security-operations agent for Kali Linux, powered by the "
            "Gemini API. Every command streams live; the safety layer enforces the scope."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Passwordless sudo (one-time setup on Kali):\n"
            '  echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/kali-agent\n'
            "  sudo chmod 440 /etc/sudoers.d/kali-agent\n"
        ),
    )
    parser.add_argument("task", nargs="*", help="Task to run immediately (optional).")
    parser.add_argument(
        "--model",
        default=None,
        help="Gemini model (default: gemini-2.5-pro, remembered in the config).",
    )
    parser.add_argument(
        "--scope",
        nargs="+",
        metavar="TARGET",
        help="Authorised targets, e.g. --scope 10.0.0.0/24 example.com",
    )
    parser.add_argument(
        "--reset-key",
        action="store_true",
        help="Delete the stored Gemini API key and ask for a new one.",
    )
    parser.add_argument(
        "--rescan",
        action="store_true",
        help="Rebuild the Kali tool catalog from apt/dpkg before starting.",
    )
    parser.add_argument(
        "--tmux",
        action="store_true",
        help="Run every command inside the tmux session 'kali-agent' "
        "(watch with: tmux attach -t kali-agent).",
    )
    parser.add_argument(
        "--unsafe",
        "--no-safety",
        "--yolo",
        dest="unsafe",
        action="store_true",
        default=None,
        help="UNCENSORED mode: no confirmation for destructive commands and no "
        "scope blocking (meant for disposable Kali Live systems). Persisted.",
    )
    parser.add_argument(
        "--safe",
        dest="unsafe",
        action="store_false",
        help="Turn the confirmation guards back on (overrides a stored unsafe=true).",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Skip the Textual TUI and use the simple console interface.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=40,
        help="Maximum tool-calling steps per task (default 40).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Default per-command timeout in seconds (default 180).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt (requires a stored key); useful for scripts.",
    )
    parser.add_argument("--version", action="version", version="kali-agent 1.0.0")
    return parser


def _require_dependencies() -> None:
    """Fail early with installation instructions when deps are missing."""

    missing: list[str] = []
    for module, package in (
        ("google.genai", "google-genai"),
        ("rich", "rich"),
        ("pexpect", "pexpect"),
    ):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing:
        print(
            "[kali-agent] missing dependencies: " + ", ".join(missing) + "\n\n"
            "Install them first:\n\n"
            "    python3 -m venv .venv && source .venv/bin/activate\n"
            "    pip install -r requirements.txt\n",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _load_registry(registry, *, force: bool = False) -> None:
    """Load the cached tool catalog, scanning when needed."""

    scanned = registry.load(force=force)
    stats = registry.stats()
    prefix = "catalog built" if scanned else "catalog loaded from cache"
    print(
        f"  · {prefix}: {stats['installed']} installed / "
        f"{stats['available']} available"
    )


def run_plain(args, config, registry, bridge) -> int:
    """Console mode (also used for --tmux). No Textual required."""

    from agent.executor import CommandExecutor
    from agent.llm import KaliAgent
    from agent.logger import SessionLogger
    from agent.memory import Memory
    from agent.safety import SafetyGuard
    from agent.tools import ToolContext, ToolDispatcher
    from ui.app import ConsoleHooks

    hooks = ConsoleHooks()
    memory = Memory(scope=config.scope)
    logger = SessionLogger(LOGS_DIR)
    executor = CommandExecutor(
        on_line=hooks.on_output,
        cwd=ROOT,
        default_timeout=args.timeout,
        tmux_bridge=bridge,
    )
    safety = SafetyGuard(config.scope, ask=hooks.ask_user, unsafe=config.unsafe)
    dispatcher = ToolDispatcher(
        ToolContext(
            executor=executor,
            registry=registry,
            safety=safety,
            memory=memory,
            logger=logger,
            hooks=hooks,  # type: ignore[arg-type]
            workspace=WORKSPACE_DIR,
            root=ROOT,
        )
    )
    agent = KaliAgent(
        api_key=config.api_key,
        model=config.model,
        dispatcher=dispatcher,
        hooks=hooks,
        logger=logger,
        memory=memory,
        max_steps=args.max_steps,
        unsafe=config.unsafe,
    )

    installed, total = registry.counts()
    logger.session_start(
        model=config.model,
        scope=config.scope,
        tools_installed=installed,
        tools_available=total,
        mode="tmux" if bridge else "plain",
        unsafe=config.unsafe,
    )

    if bridge is not None:
        hooks.console.print(
            f"[magenta]tmux live view:[/] {bridge.attach_hint()}  "
            f"(every command runs in session '{bridge.session}')"
        )

    def one_task(task: str) -> None:
        try:
            agent.send_task(task)
        except KeyboardInterrupt:
            executor.cancel()
            hooks.console.print("[red]interrupted[/]")
        hooks.console.print(
            f"[dim]{memory.status_line()}  ·  log: {logger.path}[/]", highlight=False
        )

    exit_code = 0
    try:
        for task in list(args.task):
            one_task(task)

        if args.non_interactive or not sys.stdin.isatty():
            if not args.task:
                hooks.console.print("[red]no task given (and stdin is not a TTY)[/]")
                return 2
            return exit_code

        hooks.console.print(
            "[dim]Type a task, or 'exit' to quit. Ctrl+C stops the running command.[/]"
        )
        while True:
            try:
                task = input("\nkali-agent> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not task:
                continue
            if task.lower() in {"exit", "quit", ":q", "bye"}:
                break
            if task.lower() in {"help", "?"}:
                print(
                    "  exit · help · scope <targets> · unsafe on|off   "
                    "(or just describe the task in Bangla or English)"
                )
                continue
            if task.lower() in {"unsafe on", "unsafe off", "unsafe"}:
                enabled = task.lower() != "unsafe off"
                safety.set_unsafe(enabled)
                agent.set_unsafe(enabled)
                _persist_unsafe(enabled)
                hooks.console.print(
                    f"[bold red]unsafe mode {'ON' if enabled else 'OFF'}[/]"
                    if enabled
                    else "[green]unsafe mode OFF - confirmations restored[/]"
                )
                continue
            if task.lower().startswith("scope "):
                targets = task[6:].replace(",", " ").split()
                memory.set_scope(targets)
                safety.set_scope(targets)
                hooks.on_scope(targets)
                _persist_scope(targets)
                continue
            one_task(task)
        return exit_code
    finally:
        _finish_session(memory, logger, hooks.console)


def _persist_unsafe(enabled: bool) -> None:
    """Remember the unsafe-mode choice for the next run (best effort)."""

    try:
        from agent.config import load_config, save_config

        config = load_config()
        if config is not None:
            config.unsafe = enabled
            save_config(config)
    except Exception:  # never break the session over a config write
        pass


def _persist_scope(targets: list[str]) -> None:
    """Remember the scope for the next run (best effort)."""

    try:
        from agent.config import load_config, save_config

        config = load_config()
        if config is not None:
            config.scope = targets
            save_config(config)
    except Exception:  # never break the session over a config write
        pass


def run_tui(args, config, registry) -> int:  # pragma: no cover - needs a TTY
    """Launch the Textual TUI. Returns -1 when Textual is unavailable."""

    from agent.executor import CommandExecutor
    from agent.logger import SessionLogger
    from agent.memory import Memory
    from agent.safety import SafetyGuard
    from ui.app import TEXTUAL_AVAILABLE, AppSession, KaliAgentApp

    if not TEXTUAL_AVAILABLE:
        return -1

    memory = Memory(scope=config.scope)
    logger = SessionLogger(LOGS_DIR)
    executor = CommandExecutor(cwd=ROOT, default_timeout=args.timeout)
    safety = SafetyGuard(
        config.scope, unsafe=config.unsafe
    )  # the ask callback is wired to the app below

    installed, total = registry.counts()
    logger.session_start(
        model=config.model,
        scope=config.scope,
        tools_installed=installed,
        tools_available=total,
        mode="tui",
        unsafe=config.unsafe,
    )

    session = AppSession(
        api_key=config.api_key,
        model=config.model,
        registry=registry,
        executor=executor,
        safety=safety,
        memory=memory,
        logger=logger,
        workspace=WORKSPACE_DIR,
        root=ROOT,
        max_steps=args.max_steps,
        unsafe=config.unsafe,
    )
    task = " ".join(args.task).strip() or None
    app = KaliAgentApp(session, initial_task=task)
    safety.set_ask(app.ask_user)
    app.run()

    # the app closes the log on unmount; still give the user a written report
    try:
        if memory.commands or memory.notes:
            report = WORKSPACE_DIR / f"session-{logger.session_id}.md"
            memory.export(report)
            print(f"report: {report}")
    except OSError as exc:
        print(f"could not write report: {exc}")
    return 0


def _finish_session(memory, logger, console=None) -> None:
    """Write the Markdown report and close the log."""

    try:
        if memory.commands or memory.notes:
            report = WORKSPACE_DIR / f"session-{logger.session_id}.md"
            memory.export(report)
            if console is not None:
                console.print(f"[dim]report: {report}[/]", highlight=False)
    except OSError as exc:
        if console is not None:
            console.print(f"[red]could not write report: {exc}[/]")
    logger.session_end("quit")
    logger.close()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _require_dependencies()

    from agent.config import config_summary, ensure_config, reset_api_key
    from agent.tool_registry import ToolRegistry
    from ui.tmux_bridge import TmuxBridge

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    if args.reset_key:
        reset_api_key()

    try:
        config = ensure_config(
            model=args.model,
            scope=args.scope,
            unsafe=args.unsafe,
            interactive=not args.non_interactive,
        )
    except (RuntimeError, KeyboardInterrupt) as exc:
        print(f"[kali-agent] {exc}", file=sys.stderr)
        return 2

    print(BANNER)
    print(f"  {config_summary(config)}")
    if config.unsafe:
        label = "\033[1;31mUNSAFE MODE\033[0m" if sys.stdout.isatty() else "UNSAFE MODE"
        print(
            f"  {label}: destructive commands and out-of-scope targets run WITHOUT "
            "confirmation.\n"
            "  Every command is still logged. Use --safe to restore the guards."
        )

    # --tmux: every command runs inside a visible tmux session
    bridge = None
    if args.tmux:
        if not TmuxBridge.available():
            print("  tmux: not installed (`sudo apt install tmux`) - continuing without it")
        else:
            candidate = TmuxBridge()
            if candidate.ensure_session():
                bridge = candidate
                print(f"  tmux: attach with `{bridge.attach_hint()}`")
            else:
                print("  tmux: could not create the session - continuing without it")

    print("  loading Kali tool catalog...")
    registry = ToolRegistry()
    _load_registry(registry, force=args.rescan)

    use_tui = not args.plain and not args.tmux and sys.stdout.isatty()
    if use_tui:
        code = run_tui(args, config, registry)
        if code != -1:
            return code
        print("  Textual is unavailable - falling back to console mode.")

    return run_plain(args, config, registry, bridge)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nbye.")
        raise SystemExit(130) from None
