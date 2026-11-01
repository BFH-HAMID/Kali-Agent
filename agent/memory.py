"""Session memory: scope, notes, findings and the exported Markdown report."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .executor import ExecResult


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class Note:
    """A finding or free-form note recorded by the agent."""

    text: str
    kind: str = "note"
    created_at: str = field(default_factory=_now)


@dataclass
class CommandRecord:
    """Summary of one executed command (kept for the report timeline)."""

    command: str
    exit_code: int
    duration: float
    timed_out: bool = False
    at: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @classmethod
    def from_result(cls, result: ExecResult) -> CommandRecord:
        return cls(
            command=result.command,
            exit_code=result.exit_code,
            duration=result.duration,
            timed_out=result.timed_out,
        )


class Memory:
    """Everything the agent learned during this session."""

    def __init__(self, task: str = "", scope: Sequence[str] | None = None) -> None:
        self.started_at = _now()
        self.task = task
        self.scope: list[str] = list(scope or [])
        self.notes: list[Note] = []
        self.commands: list[CommandRecord] = []
        self.finished_summary: str = ""
        self.finished_next_steps: list[str] = []

    # --------------------------------------------------------------- writes
    def add_note(self, text: str, kind: str = "note") -> Note:
        note = Note(text=text.strip(), kind=kind)
        self.notes.append(note)
        return note

    def add_finding(self, text: str) -> Note:
        return self.add_note(text, kind="finding")

    def set_scope(self, targets: Iterable[str]) -> list[str]:
        self.scope = [str(t).strip() for t in targets if str(t).strip()]
        return self.scope

    def add_command(self, result: ExecResult) -> None:
        self.commands.append(CommandRecord.from_result(result))

    def set_finish(self, summary: str, next_steps: Sequence[str] | None = None) -> None:
        self.finished_summary = summary.strip()
        self.finished_next_steps = [s for s in (next_steps or []) if s]

    # ---------------------------------------------------------------- reads
    @property
    def findings(self) -> list[Note]:
        return [n for n in self.notes if n.kind == "finding"]

    def counts(self) -> dict[str, int]:
        return {
            "notes": len(self.notes),
            "findings": len(self.findings),
            "commands": len(self.commands),
        }

    def status_line(self) -> str:
        scope = ", ".join(self.scope) if self.scope else "unrestricted"
        c = self.counts()
        return (
            f"scope: {scope} | notes: {c['notes']} | "
            f"findings: {c['findings']} | commands: {c['commands']}"
        )

    # --------------------------------------------------------------- report
    def markdown_report(self, title: str = "KaliAgent session report") -> str:
        lines: list[str] = [f"# {title}", ""]
        lines.append(f"- **Started:** {self.started_at}")
        lines.append(f"- **Generated:** {_now()}")
        lines.append(f"- **Scope:** {', '.join(self.scope) if self.scope else '(unrestricted)'}")
        lines.append("")

        lines.append("## Task")
        lines.append("")
        lines.append(self.task.strip() or "_(no task recorded)_")
        lines.append("")

        if self.finished_summary:
            lines.append("## Summary")
            lines.append("")
            lines.append(self.finished_summary)
            lines.append("")

        lines.append("## Findings")
        lines.append("")
        if self.findings:
            for note in self.findings:
                lines.append(f"- **[{note.created_at}]** {note.text}")
        else:
            lines.append("_No findings recorded._")
        lines.append("")

        other_notes = [n for n in self.notes if n.kind != "finding"]
        if other_notes:
            lines.append("## Notes")
            lines.append("")
            for note in other_notes:
                lines.append(f"- **[{note.created_at}]** {note.text}")
            lines.append("")

        lines.append("## Command timeline")
        lines.append("")
        if self.commands:
            lines.append("| Time | Exit | Duration | Command |")
            lines.append("|------|------|----------|---------|")
            for record in self.commands:
                cmd = record.command.replace("|", "\\|")
                if len(cmd) > 160:
                    cmd = cmd[:157] + "..."
                exit_code = "timeout" if record.timed_out else str(record.exit_code)
                lines.append(
                    f"| {record.at} | {exit_code} | {record.duration:.1f}s | `{cmd}` |"
                )
        else:
            lines.append("_No commands were executed._")
        lines.append("")

        if self.finished_next_steps:
            lines.append("## Suggested next steps")
            lines.append("")
            for step in self.finished_next_steps:
                lines.append(f"- {step}")
            lines.append("")

        lines.append("---")
        lines.append("_Generated by KaliAgent. Review every command before re-running it._")
        lines.append("")
        return "\n".join(lines)

    def export(self, path: str | Path, title: str = "KaliAgent session report") -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.markdown_report(title), encoding="utf-8")
        return target


__all__ = ["CommandRecord", "Memory", "Note"]
