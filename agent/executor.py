"""Command execution with live streaming, timeouts and cancellation.

Design notes
------------
* stdout and stderr are merged and streamed **line by line** to a callback, so
  the UI can show what is happening while it happens.
* Every command runs in its own process group; on timeout or Ctrl+C the whole
  group is killed (``SIGKILL``) so that ``nmap``/``msfconsole`` child processes
  do not survive.
* Only the *tail* of the output is handed back to the model (default 8000
  characters, configurable) while the full output is kept for the log file.
* ``sudo`` works non-interactively because the user has passwordless sudo; we
  never feed a password to the child.
* Interactive programs (``msfconsole``, ``ssh``, ``ftp``) are driven through
  ``pexpect`` by :meth:`CommandExecutor.run_interactive`.
"""

from __future__ import annotations

import os
import queue
import shlex
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

#: Called for every streamed output line (without trailing newline).
LineCallback = Callable[[str], None]

#: Hard cap for the in-memory copy of a command's output (chars).
MAX_CAPTURE_CHARS = 2_000_000

#: Default number of trailing characters returned to the model.
DEFAULT_RETURN_CHARS = 8_000

#: Environment tweaks that stop tools from waiting for a human/pager.
_SAFE_ENV_EXTRA: dict[str, str] = {
    "TERM": "dumb",
    "NO_COLOR": "1",
    "PAGER": "cat",
    "MANPAGER": "cat",
    "GIT_PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "DEBIAN_FRONTEND": "noninteractive",
    "APT_LISTCHANGES_FRONTEND": "none",
    "PYTHONUNBUFFERED": "1",
}


@dataclass
class ExecResult:
    """Outcome of one command."""

    command: str
    exit_code: int = 0
    output: str = ""          # tail of the output, safe to give to the model
    full_output: str = ""     # everything we captured (for logs)
    duration: float = 0.0
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    started_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    # ------------------------------------------------------------------
    def to_tool_response(self) -> dict[str, object]:
        """Compact JSON-able payload for a Gemini function response."""

        response: dict[str, object] = {
            "exit_code": self.exit_code,
            "output": self.output,
            "duration_s": round(self.duration, 2),
        }
        if self.timed_out:
            response["timed_out"] = True
        if self.cancelled:
            response["cancelled"] = True
        if self.truncated:
            response["note"] = (
                "output truncated - only the tail is shown; the full output was "
                "logged. Use grep/head/tail or redirect to ./workspace to inspect more."
            )
        return response

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


class CommandExecutor:
    """Run shell commands with streaming, timeouts and cancellation."""

    def __init__(
        self,
        on_line: LineCallback | None = None,
        *,
        cwd: str | Path | None = None,
        default_timeout: float = 180.0,
        max_return_chars: int = DEFAULT_RETURN_CHARS,
        tmux_bridge: object | None = None,
    ) -> None:
        self.on_line = on_line
        self.cwd = Path(cwd) if cwd else Path.cwd()
        self.default_timeout = float(default_timeout)
        self.max_return_chars = int(max_return_chars)
        self.tmux_bridge = tmux_bridge

        self._proc: subprocess.Popen[str] | None = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.current_command: str = ""

    # ------------------------------------------------------------- helpers
    def _emit(self, line: str) -> None:
        if self.on_line is None:
            return
        try:
            self.on_line(line)
        except Exception:  # a broken UI must never kill the agent
            pass

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(_SAFE_ENV_EXTRA)
        return env

    @staticmethod
    def _kill_group(proc: subprocess.Popen[str]) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    # ---------------------------------------------------------------- state
    def cancel(self) -> None:
        """Cancel the running command (called from a UI thread / Ctrl+C)."""

        self._cancel.set()
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            self._kill_group(proc)

    def reset_cancel(self) -> None:
        self._cancel.clear()

    @property
    def running(self) -> bool:
        with self._lock:
            proc = self._proc
        return proc is not None and proc.poll() is None

    # ------------------------------------------------------------------ run
    def run(
        self,
        command: str,
        timeout: float | None = None,
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecResult:
        """Run ``command`` through ``bash`` and stream it live."""

        command = command.strip()
        if not command:
            return ExecResult(command=command, exit_code=2, output="empty command")

        if self.tmux_bridge is not None:
            return self._run_via_tmux(command, timeout)

        timeout = float(timeout) if timeout else self.default_timeout
        if timeout <= 0:
            timeout = self.default_timeout

        self._cancel.clear()
        self.current_command = command
        started = time.monotonic()
        result = ExecResult(command=command)

        child_env = self._env()
        if env:
            child_env.update({str(k): str(v) for k, v in env.items()})

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                executable="/bin/bash",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(cwd or self.cwd),
                env=child_env,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            result.exit_code = 127
            result.output = f"failed to start command: {exc}"
            result.full_output = result.output
            result.duration = time.monotonic() - started
            self._emit(result.output)
            return result

        with self._lock:
            self._proc = proc
        self._emit(f"$ {command}")

        lines: queue.Queue[str | None] = queue.Queue()

        def _reader() -> None:
            stream = proc.stdout
            try:
                if stream is not None:
                    for line in stream:
                        lines.put(line)
            except (OSError, ValueError):
                pass
            finally:
                lines.put(None)

        reader = threading.Thread(target=_reader, name="kali-agent-reader", daemon=True)
        reader.start()

        chunks: list[str] = []
        captured = 0
        deadline = started + timeout
        timed_out = False

        try:
            while True:
                if self._cancel.is_set():
                    result.cancelled = True
                    self._kill_group(proc)
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._kill_group(proc)
                    break

                try:
                    item = lines.get(timeout=min(0.2, max(remaining, 0.01)))
                except queue.Empty:
                    if proc.poll() is not None:
                        # give the reader a moment to flush the last lines
                        try:
                            item = lines.get(timeout=0.2)
                        except queue.Empty:
                            break
                        if item is None:
                            break
                    else:
                        continue

                if item is None:
                    break

                text = item.rstrip("\n")
                self._emit(text)
                if captured < MAX_CAPTURE_CHARS:
                    chunks.append(text + "\n")
                    captured += len(text) + 1

        except KeyboardInterrupt:
            # Ctrl+C: kill the whole process group, reap it, and let the
            # caller decide what to do (the agent loop logs the interrupt).
            self._kill_group(proc)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:  # pragma: no cover
                pass
            with self._lock:
                self._proc = None
            raise
        try:
            exit_code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._kill_group(proc)
            exit_code = proc.wait(timeout=5) if proc.poll() is not None else -9

        # drain anything still buffered
        while True:
            try:
                item = lines.get_nowait()
            except queue.Empty:
                break
            if item is None:
                break
            text = item.rstrip("\n")
            self._emit(text)
            if captured < MAX_CAPTURE_CHARS:
                chunks.append(text + "\n")
                captured += len(text) + 1

        reader.join(timeout=1.0)
        with self._lock:
            self._proc = None

        full = "".join(chunks)
        # a cancel can arrive while the child is dying: EOF wakes the loop
        # before the flag is re-read, so check it once more here.
        if self._cancel.is_set():
            result.cancelled = True
        if timed_out:
            exit_code = -1
            timeout_note = f"[killed after {timeout:.0f}s timeout]"
            self._emit(timeout_note)
            full += timeout_note + "\n"
        if result.cancelled:
            exit_code = -1
            full += "[cancelled by user]\n"

        result.exit_code = int(exit_code)
        result.full_output = full
        result.timed_out = timed_out
        result.duration = time.monotonic() - started
        result.output, result.truncated = self._tail(full)
        return result

    # ------------------------------------------------------------- tmux run
    def _run_via_tmux(self, command: str, timeout: float | None) -> ExecResult:
        """Delegate to the tmux bridge (commands run in a visible pane)."""

        bridge = self.tmux_bridge
        self.current_command = command
        self._cancel.clear()
        run = getattr(bridge, "run", None)
        if run is None:  # pragma: no cover - defensive
            return self.run(command, timeout)
        result = run(
            command,
            timeout=timeout or self.default_timeout,
            on_line=self._emit,
            cwd=self.cwd,
        )
        if isinstance(result, ExecResult):
            return result
        return ExecResult(command=command, exit_code=1, output=str(result))

    # ------------------------------------------------------ interactive run
    def run_interactive(
        self,
        command: str,
        inputs: Sequence[str] | str | None = None,
        *,
        timeout: float | None = None,
        expect_reply_timeout: float = 30.0,
    ) -> ExecResult:
        """Drive an interactive program with pexpect.

        ``inputs`` is a list of lines that are sent whenever the program looks
        like it is waiting for something (a prompt, ``y/n`` question, password
        prompt, shell prompt...).  All output is streamed live.
        """

        if isinstance(inputs, str):
            inputs = [inputs]
        answers = [str(i) for i in (inputs or [])]
        timeout = float(timeout) if timeout else max(self.default_timeout, 120.0)

        command = command.strip()
        if not command:
            return ExecResult(command=command, exit_code=2, output="empty command")

        self._cancel.clear()
        self.current_command = command
        started = time.monotonic()
        self._emit(f"$ {command}   (interactive)")

        try:
            import pexpect  # imported lazily so the CLI works without it
        except ImportError:  # pragma: no cover - optional dependency
            self._emit("[pexpect not installed - falling back to a plain run]")
            return self.run(command, timeout)

        captured: list[str] = []
        adapter = _StreamAdapter(self._emit, captured)

        try:
            child = pexpect.spawn(
                "/bin/bash",
                ["-lc", command],
                timeout=min(expect_reply_timeout, timeout),
                encoding="utf-8",
                codec_errors="replace",
                logfile=adapter,
                cwd=str(self.cwd),
                env=self._env(),
                dimensions=(40, 160),
            )
        except (pexpect.ExceptionPexpect, OSError) as exc:
            return ExecResult(
                command=command,
                exit_code=127,
                output=f"failed to spawn: {exc}",
                full_output=f"failed to spawn: {exc}",
                duration=time.monotonic() - started,
            )

        with self._lock:
            self._proc = child  # type: ignore[assignment]

        prompt_patterns = [
            r"(?i)password\s*:",
            r"(?i)passphrase\s*:",
            r"(?i)\[y/n\]",
            r"(?i)\[y/N\]",
            r"(?i)\(yes/no",
            r"(?i)press\s+(enter|any key)",
            r"(?i)are you sure",
            r"[#>$]\s*$",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ]

        timed_out = False
        try:
            eof_index = len(prompt_patterns) - 2
            for answer in answers:
                if self._cancel.is_set():
                    break
                index = child.expect(
                    prompt_patterns, timeout=min(expect_reply_timeout, timeout)
                )
                if index == eof_index + 1:  # EOF: the program already exited
                    break
                # index == eof_index means TIMEOUT: send the line anyway, the
                # program may simply not print a recognisable prompt.
                child.sendline(answer)
            if not self._cancel.is_set():
                while True:
                    index = child.expect(
                        [pexpect.EOF, pexpect.TIMEOUT],
                        timeout=max(1.0, timeout - (time.monotonic() - started)),
                    )
                    if index == 0:
                        break
                    timed_out = True
                    break
        except pexpect.TIMEOUT:
            timed_out = True
        except pexpect.EOF:
            pass
        except (OSError, ValueError) as exc:
            adapter.write(f"\n[pexpect error: {exc}]\n")
        finally:
            if self._cancel.is_set() or timed_out:
                try:
                    child.terminate(force=True)
                except Exception:  # pragma: no cover - best effort
                    pass
            try:
                child.close(force=True)
            except Exception:  # pragma: no cover - best effort
                pass
            with self._lock:
                self._proc = None

        full = "".join(captured)
        if timed_out:
            full += f"\n[killed after {timeout:.0f}s timeout]\n"
        if self._cancel.is_set():
            full += "\n[cancelled by user]\n"

        exit_code = child.exitstatus
        if exit_code is None:
            exit_code = -1

        result = ExecResult(
            command=command,
            exit_code=int(exit_code),
            full_output=full,
            duration=time.monotonic() - started,
            timed_out=timed_out,
            cancelled=self._cancel.is_set(),
        )
        result.output, result.truncated = self._tail(full)
        return result

    # ------------------------------------------------------------- utility
    def _tail(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.max_return_chars:
            return text, False
        return text[-self.max_return_chars:], True

    def shell_quote(self, value: str) -> str:
        return shlex.quote(value)

    def exists(self, binary: str) -> bool:
        from shutil import which

        return which(binary) is not None

    def iter_bin_dirs(self) -> Iterable[Path]:
        for directory in ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/sbin", "/bin"):
            path = Path(directory)
            if path.is_dir():
                yield path


class _StreamAdapter:
    """File-like object that forwards pexpect output to the callback."""

    def __init__(self, on_line: LineCallback | None, sink: list[str]) -> None:
        self._on_line = on_line
        self._sink = sink
        self._buffer = ""

    def write(self, data: str | bytes) -> int:
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        normalised = data.replace("\r\n", "\n").replace("\r", "\n")
        self._sink.append(normalised)
        self._buffer += normalised
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if self._on_line is not None:
                try:
                    self._on_line(line)
                except Exception:
                    pass
        return len(data)

    def flush(self) -> None:
        if self._buffer and self._on_line is not None:
            try:
                self._on_line(self._buffer)
            except Exception:
                pass
            self._buffer = ""


__all__ = [
    "CommandExecutor",
    "DEFAULT_RETURN_CHARS",
    "ExecResult",
    "MAX_CAPTURE_CHARS",
]
