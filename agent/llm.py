"""Gemini client and the manual function-calling agent loop.

``automatic_function_calling`` is explicitly disabled: the loop
(:meth:`KaliAgent.send_task`) reads ``resp.function_calls``, executes each call
through :class:`agent.tools.ToolDispatcher` (which applies the safety gate),
sends the results back as ``function_response`` parts, and repeats until the
model stops asking for tools.

Robustness: exponential backoff on rate limits / 5xx, graceful Ctrl+C (the
running subprocess is killed, the session log stays valid), and a hard step
limit so a confused model cannot loop forever.
"""

from __future__ import annotations

import json
import random
import time
from typing import Any

from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from .logger import SessionLogger
from .memory import Memory
from .system_prompt import build_system_prompt
from .tools import AgentFinished, ToolDispatcher

#: HTTP-ish status codes worth retrying.
RETRYABLE_CODES = frozenset({408, 409, 429, 500, 502, 503, 504})

#: Substrings that indicate a transient failure even without a status code.
RETRYABLE_HINTS = (
    "429",
    "rate limit",
    "quota",
    "resource exhausted",
    "503",
    "unavailable",
    "overloaded",
    "deadline exceeded",
    "timeout",
    "internal error",
    "connection reset",
    "connection error",
    "connect",
    "network",
    "temporarily",
    "name resolution",
    "ssl",
)


class AgentHooks:
    """UI callbacks. The base class is a no-op implementation (used in tests)."""

    def on_status(self, text: str) -> None:  # pragma: no cover - trivial
        pass

    def on_assistant_text(self, text: str) -> None:  # pragma: no cover
        pass

    def on_tool_call(self, name: str, args: dict[str, Any]) -> None:  # pragma: no cover
        pass

    def on_output(self, line: str) -> None:  # pragma: no cover
        pass

    def on_command_result(
        self, command: str, exit_code: int, duration: float, timed_out: bool
    ) -> None:  # pragma: no cover
        pass

    def on_scope(self, scope: list[str]) -> None:  # pragma: no cover
        pass

    def ask_user(self, question: str, kind: str = "yesno") -> bool:  # pragma: no cover
        return False


def _is_retryable(exc: BaseException) -> bool:
    """Decide whether an API failure is worth another attempt."""

    code = getattr(exc, "code", None)
    if isinstance(code, int) and code in RETRYABLE_CODES:
        return True
    status = getattr(exc, "status", None)
    if isinstance(status, str) and status.upper() in {"RESOURCE_EXHAUSTED", "UNAVAILABLE"}:
        return True
    message = str(exc).lower()
    return any(hint in message for hint in RETRYABLE_HINTS)


def _jsonable(payload: Any) -> Any:
    """Make sure a tool result survives JSON/protobuf serialisation."""

    try:
        return json.loads(json.dumps(payload, default=str))
    except (TypeError, ValueError):
        return {"result": str(payload)}


def _as_args(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    try:
        return dict(raw)  # pydantic-like mapping
    except (TypeError, ValueError):
        return {}


def extract_text(response: Any) -> str:
    """Best-effort text extraction from a GenerateContentResponse."""

    text = ""
    try:
        candidate = response.text
        if candidate:
            text = candidate
    except (AttributeError, ValueError):
        text = ""
    if text:
        return text.strip()

    # fall back to walking the parts (thinking models can split the answer)
    try:
        for candidate in getattr(response, "candidates", None) or []:
            content = getattr(candidate, "content", None)
            for part in getattr(content, "parts", None) or []:
                piece = getattr(part, "text", None)
                if piece and not getattr(part, "thought", False):
                    text += piece
    except Exception:  # pragma: no cover - defensive only
        pass
    return text.strip()


def extract_usage(response: Any) -> dict[str, int]:
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return {}
    mapping = {
        "prompt_tokens": "prompt_token_count",
        "output_tokens": "candidates_token_count",
        "total_tokens": "total_token_count",
    }
    result: dict[str, int] = {}
    for key, attr in mapping.items():
        value = getattr(usage, attr, None)
        if isinstance(value, int):
            result[key] = value
    return result


class KaliAgent:
    """Drives one Gemini chat session with manual function calling."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        dispatcher: ToolDispatcher,
        hooks: AgentHooks | None = None,
        logger: SessionLogger | None = None,
        memory: Memory | None = None,
        max_steps: int = 40,
        temperature: float = 0.2,
        unsafe: bool = False,
    ) -> None:
        self.model = model
        self.dispatcher = dispatcher
        self.hooks: AgentHooks = hooks or AgentHooks()
        self.logger = logger or SessionLogger(echo=False)
        self.memory = memory or Memory()
        self.max_steps = max(1, int(max_steps))
        self.temperature = temperature
        self.unsafe = bool(unsafe)

        self._client = genai.Client(api_key=api_key)
        self._chat: Any = None
        self._busy = False

    # ------------------------------------------------------------------ chat
    def _config(self) -> types.GenerateContentConfig:
        return types.GenerateContentConfig(
            system_instruction=build_system_prompt(self.unsafe),
            tools=[types.Tool(function_declarations=self.dispatcher.declarations)],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            temperature=self.temperature,
        )

    def _ensure_chat(self) -> Any:
        if self._chat is None:
            self._chat = self._client.chats.create(model=self.model, config=self._config())
        return self._chat

    def reset(self) -> None:
        """Drop the conversation history (scope/notes are kept)."""

        self._chat = None

    def set_unsafe(self, unsafe: bool) -> None:
        """Switch uncensored mode on/off and rebuild the prompt on next task."""

        if bool(unsafe) != self.unsafe:
            self.unsafe = bool(unsafe)
            self._chat = None  # the system instruction is part of the chat config

    # ---------------------------------------------------------------- calls
    def _send(self, message: Any) -> Any:
        """Send a message, retrying transient API failures with backoff."""

        chat = self._ensure_chat()
        attempt = 0
        while True:
            try:
                return chat.send_message(message)
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # API, transport and TLS errors alike
                attempt += 1
                if attempt > 5 or not _is_retryable(exc):
                    self.logger.error(f"Gemini API error: {exc}", attempt=attempt)
                    raise
                delay = min(60.0, 2.0 ** attempt) + random.uniform(0, 1.0)
                self.logger.error(
                    f"Gemini API error (retrying in {delay:.0f}s): {exc}", attempt=attempt
                )
                self.hooks.on_status(
                    f"API error, retrying in {delay:.0f}s (attempt {attempt}/5): {exc}"
                )
                time.sleep(delay)

    # ------------------------------------------------------------- main loop
    def send_task(self, task: str) -> str:
        """Run one task to completion and return the final assistant text."""

        task = task.strip()
        if not task:
            return ""
        self.memory.task = task
        self.logger.user_task(task)
        new_task = getattr(self.dispatcher, "new_task", None)
        if callable(new_task):
            new_task()
        self._busy = True
        self.hooks.on_status(f"thinking... ({self.model})")

        try:
            response = self._send(task)
        except KeyboardInterrupt:
            self._busy = False
            self._cancel_running_command()
            self.hooks.on_status("interrupted")
            self.logger.log("interrupted", phase="initial_request")
            return "Interrupted before the model answered."
        except Exception as exc:
            self._busy = False
            self.logger.error(f"request failed: {exc}")
            self.hooks.on_status(f"request failed: {exc}")
            return f"Gemini request failed: {exc}"

        steps = 0
        final_text = ""

        while True:
            steps += 1
            try:
                text = extract_text(response)
                if text:
                    final_text = text
                    self.logger.assistant_text(text)
                    self.hooks.on_assistant_text(text)

                usage = extract_usage(response)
                if usage:
                    self.logger.log("usage", **usage)

                calls = list(getattr(response, "function_calls", None) or [])
                if not calls:
                    self._busy = False
                    self.logger.log("task_complete", steps=steps)
                    self.hooks.on_status("ready")
                    return final_text or "(the agent finished without a text answer)"

                if steps > self.max_steps:
                    message = (
                        f"Stopped after {self.max_steps} steps without finishing. "
                        "Ask the user how to continue."
                    )
                    self.hooks.on_assistant_text(message)
                    self.logger.error(message)
                    self._busy = False
                    return message

                finished: AgentFinished | None = None
                parts: list[types.Part] = []

                for call in calls:
                    name = getattr(call, "name", "") or ""
                    args = _as_args(getattr(call, "args", None))
                    self.hooks.on_tool_call(name, args)
                    self.logger.tool_call(name, _jsonable(args))

                    try:
                        result = self.dispatcher.dispatch(name, args)
                    except AgentFinished as done:
                        finished = done
                        break
                    except KeyboardInterrupt:
                        raise
                    except Exception as exc:  # tool crash -> tell the model
                        result = {"error": f"{name} crashed: {exc}"}

                    parts.append(
                        types.Part.from_function_response(
                            name=name, response={"result": _jsonable(result)}
                        )
                    )

                if finished is not None:
                    self.logger.finish(finished.summary, finished.report_path)
                    self.hooks.on_assistant_text(finished.summary)
                    if finished.report_path:
                        self.hooks.on_status(f"report saved: {finished.report_path}")
                    if finished.next_steps:
                        self.memory.set_finish(finished.summary, finished.next_steps)
                    self._busy = False
                    return finished.summary

                if not parts:
                    self._busy = False
                    return final_text or "(no tool results were produced)"

                self.hooks.on_status("thinking...")
                response = self._send(parts)

            except KeyboardInterrupt:
                self._busy = False
                self._cancel_running_command()
                self.hooks.on_status("interrupted")
                self.logger.log("interrupted", phase="loop", steps=steps)
                return "Interrupted by user."
            except (genai_errors.APIError, OSError, TimeoutError) as exc:
                self._busy = False
                self.logger.error(f"Gemini API error: {exc}", steps=steps)
                self.hooks.on_status(f"API error: {exc}")
                return f"Gemini API error: {exc}"
            except Exception as exc:  # pragma: no cover - unexpected
                self._busy = False
                self.logger.error(f"agent loop error: {exc}", steps=steps)
                self.hooks.on_status(f"error: {exc}")
                return f"Agent loop error: {exc}"

    # ------------------------------------------------------------- helpers
    def _cancel_running_command(self) -> None:
        executor = getattr(getattr(self.dispatcher, "ctx", None), "executor", None)
        cancel = getattr(executor, "cancel", None)
        if callable(cancel):
            try:
                cancel()
            except Exception:
                pass

    @property
    def busy(self) -> bool:
        return self._busy


__all__ = [
    "AgentHooks",
    "KaliAgent",
    "RETRYABLE_CODES",
    "extract_text",
    "extract_usage",
]
