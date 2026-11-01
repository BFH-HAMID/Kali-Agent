"""Run every command inside a tmux session so the user can watch/attach.

How it works
------------
For each command we write a tiny runner script and paste it into the
``kali-agent`` tmux session with ``send-keys``.  The script pipes the command
through ``tee`` so the output appears **live in the tmux pane** *and* lands in a
log file that KaliAgent tails to stream the same lines into its own UI and to
build the model's truncated result.  The exit code is written to the log as a
sentinel line, which is how we know the command finished.

Attach any time with::

    tmux attach -t kali-agent
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from agent.executor import ExecResult

LineCallback = Callable[[str], None]

#: Line the runner appends once the command finished: ``__KALI_EXIT__:<code>``.
EXIT_SENTINEL = "__KALI_EXIT__:"


class TmuxBridge:
    """Thin wrapper around a dedicated tmux session."""

    def __init__(
        self,
        session: str = "kali-agent",
        *,
        run_dir: str | Path | None = None,
        poll_interval: float = 0.15,
    ) -> None:
        self.session = session
        self.run_root = Path(run_dir or (Path(tempfile.gettempdir()) / "kali-agent-tmux"))
        self.poll_interval = poll_interval
        self._current_run_dir: Path | None = None

    # ------------------------------------------------------------- session
    @staticmethod
    def available() -> bool:
        return shutil.which("tmux") is not None

    def _tmux(self, *args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["tmux", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )

    def has_session(self) -> bool:
        if not self.available():
            return False
        try:
            return self._tmux("has-session", "-t", self.session).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def ensure_session(self) -> bool:
        """Create the session when needed. Returns True when it is available."""

        if not self.available():
            return False
        if self.has_session():
            return True
        try:
            proc = self._tmux(
                "new-session", "-d", "-s", self.session, "-x", "200", "-y", "50"
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if proc.returncode != 0:
            return False
        # keep a decent scrollback for the human watching the pane
        self._tmux("set-option", "-t", self.session, "history-limit", "50000")
        return True

    def attach_hint(self) -> str:
        return f"tmux attach -t {self.session}"

    def kill_session(self) -> None:
        if self.has_session():
            try:
                self._tmux("kill-session", "-t", self.session)
            except (OSError, subprocess.SubprocessError):
                pass

    # ----------------------------------------------------------------- run
    def run(
        self,
        command: str,
        timeout: float = 180.0,
        on_line: LineCallback | None = None,
        cwd: str | Path | None = None,
    ) -> ExecResult:
        """Run ``command`` in the tmux pane and stream its output."""

        started = time.monotonic()
        command = command.strip()
        if not command:
            return ExecResult(command=command, exit_code=2, output="empty command")

        if not self.ensure_session():
            return ExecResult(
                command=command,
                exit_code=127,
                output=(
                    "tmux is not available - install it (sudo apt install tmux) or run "
                    "KaliAgent without --tmux."
                ),
                duration=time.monotonic() - started,
            )

        run_dir = self.run_root / f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        run_dir.mkdir(parents=True, exist_ok=True)
        out_file = run_dir / "out.log"
        done_file = run_dir / "done"
        cmd_file = run_dir / "cmd.sh"
        runner = run_dir / "run.sh"

        working_dir = str(Path(cwd).expanduser()) if cwd else os.getcwd()

        cmd_file.write_text(command + "\n", encoding="utf-8")
        runner.write_text(
            "#!/bin/bash\n"
            f"cd {shlex.quote(working_dir)} || exit 1\n"
            f": > {shlex.quote(str(out_file))}\n"
            f"stdbuf -oL -eL bash {shlex.quote(str(cmd_file))} 2>&1 "
            f"| tee -a {shlex.quote(str(out_file))}\n"
            "code=${PIPESTATUS[0]}\n"
            f'echo "{EXIT_SENTINEL}${{code}}" >> {shlex.quote(str(out_file))}\n'
            f"echo done > {shlex.quote(str(done_file))}\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        self._current_run_dir = run_dir

        if on_line is not None:
            try:
                on_line(f"$ {command}   [tmux:{self.session}]")
            except Exception:
                pass

        try:
            self._tmux(
                "send-keys", "-t", self.session, f"bash {shlex.quote(str(runner))}", "Enter"
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ExecResult(
                command=command,
                exit_code=127,
                output=f"could not talk to tmux: {exc}",
                duration=time.monotonic() - started,
            )

        # The pane may not have created the log yet: create it ourselves so the
        # tail below can never race the shell that is starting up.
        out_file.touch(exist_ok=True)

        chunks: list[str] = []
        buffer = ""
        exit_code: int | None = None
        timed_out = False
        deadline = started + max(timeout, 1.0)

        with out_file.open("r", encoding="utf-8", errors="replace") as handle:
            while True:
                chunk = handle.read()
                if chunk:
                    chunks.append(chunk)
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if line.startswith(EXIT_SENTINEL):
                            try:
                                exit_code = int(line[len(EXIT_SENTINEL):].strip())
                            except ValueError:
                                exit_code = -1
                            continue
                        if on_line is not None:
                            try:
                                on_line(line)
                            except Exception:
                                pass

                if done_file.exists() and exit_code is not None:
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    self.interrupt()
                    break
                time.sleep(self.poll_interval)

            # flush whatever arrived after the last newline
            if buffer and not buffer.startswith(EXIT_SENTINEL):
                if on_line is not None:
                    try:
                        on_line(buffer)
                    except Exception:
                        pass
                chunks.append("\n")

        full = "".join(chunks)
        # drop the sentinel line from the captured text
        full = "\n".join(
            line for line in full.split("\n") if not line.startswith(EXIT_SENTINEL)
        )

        if timed_out:
            exit_code = -1
            full += f"\n[killed after {timeout:.0f}s timeout]\n"
        if exit_code is None:
            exit_code = -1

        result = ExecResult(
            command=command,
            exit_code=int(exit_code),
            full_output=full,
            duration=time.monotonic() - started,
            timed_out=timed_out,
        )
        result.output, result.truncated = _tail(full, 8000)
        return result

    # ------------------------------------------------------------ interrupt
    def interrupt(self) -> None:
        """Send Ctrl+C to the session (used on timeout / user cancel)."""

        if not self.has_session():
            return
        try:
            self._tmux("send-keys", "-t", self.session, "C-c")
        except (OSError, subprocess.SubprocessError):
            pass


def _tail(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[-limit:], True


__all__ = ["EXIT_SENTINEL", "TmuxBridge"]
