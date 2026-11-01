"""Unit tests for the command executor (streaming, timeout, cancel, pexpect)."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.executor import CommandExecutor, ExecResult  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX only")


# --------------------------------------------------------------------------
# basic execution
# --------------------------------------------------------------------------


def test_simple_command_succeeds() -> None:
    executor = CommandExecutor()
    result = executor.run("echo hello-kali")
    assert result.exit_code == 0
    assert "hello-kali" in result.output
    assert result.timed_out is False
    assert result.ok is True
    assert result.duration >= 0


def test_non_zero_exit_code_is_reported() -> None:
    executor = CommandExecutor()
    result = executor.run("exit 3")
    assert result.exit_code == 3
    assert result.ok is False


def test_stderr_is_merged_into_output() -> None:
    executor = CommandExecutor()
    result = executor.run("echo out; echo err >&2")
    assert "out" in result.output
    assert "err" in result.output


def test_empty_command_is_rejected() -> None:
    executor = CommandExecutor()
    result = executor.run("   ")
    assert result.exit_code == 2
    assert "empty" in result.output.lower()


def test_cwd_is_respected(tmp_path: Path) -> None:
    executor = CommandExecutor(cwd=tmp_path)
    result = executor.run("pwd")
    assert str(tmp_path) in result.output


# --------------------------------------------------------------------------
# streaming
# --------------------------------------------------------------------------


def test_output_is_streamed_line_by_line() -> None:
    lines: list[str] = []
    executor = CommandExecutor(on_line=lines.append)
    executor.run("printf 'one\\ntwo\\nthree\\n'")

    assert lines[0].startswith("$ ")  # the echoed command
    assert "one" in lines
    assert "two" in lines
    assert "three" in lines


def test_streaming_callback_errors_do_not_break_execution() -> None:
    def boom(_line: str) -> None:
        raise RuntimeError("ui exploded")

    executor = CommandExecutor(on_line=boom)
    result = executor.run("echo still-works")
    assert result.exit_code == 0
    assert "still-works" in result.output


# --------------------------------------------------------------------------
# truncation / limits
# --------------------------------------------------------------------------


def test_output_is_truncated_for_the_model() -> None:
    executor = CommandExecutor(max_return_chars=100)
    result = executor.run("python3 -c \"print('x' * 5000)\"")
    assert result.truncated is True
    assert len(result.output) <= 100
    assert len(result.full_output) > 100
    payload = result.to_tool_response()
    assert payload["output"] == result.output
    assert "note" in payload


def test_short_output_is_not_truncated() -> None:
    executor = CommandExecutor()
    result = executor.run("echo short")
    assert result.truncated is False
    assert result.output == "short\n"


# --------------------------------------------------------------------------
# timeout / cancellation
# --------------------------------------------------------------------------


def test_timeout_kills_the_command() -> None:
    executor = CommandExecutor()
    started = time.monotonic()
    result = executor.run("sleep 30", timeout=0.5)
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert result.exit_code == -1
    assert elapsed < 5
    assert "timeout" in result.output.lower()


def test_child_processes_are_killed_on_timeout() -> None:
    executor = CommandExecutor()
    result = executor.run("bash -c 'sleep 30 & wait'", timeout=0.5)
    assert result.timed_out is True
    # no sleep process from this command may survive
    check = executor.run("pgrep -f 'sleep 30' || true")
    assert "sleep 30" not in check.output


def test_cancel_stops_a_running_command() -> None:
    executor = CommandExecutor()
    outcome: dict[str, ExecResult] = {}

    def worker() -> None:
        outcome["result"] = executor.run("sleep 30", timeout=60)

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.6)
    executor.cancel()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert outcome["result"].cancelled is True
    assert outcome["result"].exit_code == -1


# --------------------------------------------------------------------------
# interactive (pexpect)
# --------------------------------------------------------------------------


def test_run_interactive_answers_prompts(tmp_path: Path) -> None:
    pexpect = pytest.importorskip("pexpect")

    script = tmp_path / "ask.py"
    script.write_text(
        "print('Name?')\n"
        "import sys\n"
        "name = sys.stdin.readline().strip()\n"
        "print('hello', name)\n",
        encoding="utf-8",
    )

    lines: list[str] = []
    executor = CommandExecutor(on_line=lines.append, cwd=tmp_path)
    result = executor.run_interactive(
        f"{sys.executable} {script}", ["world"], timeout=20, expect_reply_timeout=2
    )

    assert "hello world" in result.full_output
    assert any("Name?" in line for line in lines)
    del pexpect
