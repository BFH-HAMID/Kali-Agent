"""JSONL session logging.

Every meaningful event - user task, assistant reasoning, tool call, command,
its full output, exit code and duration - is appended to
``logs/<session>.jsonl`` as one JSON object per line. The format is trivially
greppable and easy to post-process with ``jq``.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .executor import ExecResult

#: Default location of the log directory (``<project>/logs``).
DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"


def new_session_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class SessionLogger:
    """Append-only JSONL logger, safe to call from multiple threads."""

    def __init__(
        self,
        log_dir: str | Path = DEFAULT_LOG_DIR,
        session_id: str | None = None,
        *,
        echo: bool = False,
    ) -> None:
        self.session_id = session_id or new_session_id()
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / f"{self.session_id}.jsonl"
        self.echo = echo
        self._lock = threading.Lock()
        self._handle = self.path.open("a", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover
            pass

    # ----------------------------------------------------------------- write
    def log(self, event: str, **data: Any) -> None:
        """Append one event to the log file."""

        record: dict[str, Any] = {"ts": _now(), "event": event}
        record.update(data)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            if self._handle.closed:
                return
            self._handle.write(line + "\n")
            self._handle.flush()
        if self.echo:
            print(line)

    # --------------------------------------------------------------- events
    def session_start(self, **info: Any) -> None:
        self.log("session_start", session=self.session_id, **info)

    def session_end(self, reason: str = "quit") -> None:
        self.log("session_end", reason=reason)

    def user_task(self, text: str) -> None:
        self.log("user_task", text=text)

    def assistant_text(self, text: str) -> None:
        self.log("assistant_text", text=text)

    def tool_call(self, name: str, args: dict[str, Any]) -> None:
        self.log("tool_call", name=name, args=args)

    def tool_result(self, name: str, result: Any) -> None:
        self.log("tool_result", name=name, result=result)

    def command(self, result: ExecResult, *, tool: str = "run_command") -> None:
        """Log a finished command, including its full output."""

        self.log(
            "command",
            tool=tool,
            command=result.command,
            exit_code=result.exit_code,
            duration_s=round(result.duration, 3),
            timed_out=result.timed_out,
            cancelled=result.cancelled,
            started_at=result.started_at,
            output=result.full_output,
            returned_chars=len(result.output),
            truncated=result.truncated,
        )

    def note(self, text: str, kind: str = "note") -> None:
        self.log("note", kind=kind, text=text)

    def scope(self, targets: list[str]) -> None:
        self.log("scope", targets=targets)

    def answer(self, question: str, approved: bool) -> None:
        self.log("user_answer", question=question, approved=approved)

    def status(self, text: str) -> None:
        self.log("status", text=text)

    def error(self, message: str, **data: Any) -> None:
        self.log("error", message=message, **data)

    def finish(self, summary: str, report_path: str | None = None) -> None:
        self.log("finish", summary=summary, report_path=report_path)

    # ---------------------------------------------------------------- close
    def close(self) -> None:
        with self._lock:
            if not self._handle.closed:
                self._handle.close()

    @property
    def closed(self) -> bool:
        return self._handle.closed

    def __enter__(self) -> SessionLogger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = ["DEFAULT_LOG_DIR", "SessionLogger", "new_session_id"]
