"""User interfaces: the Textual TUI and the plain console renderer."""

from __future__ import annotations

__all__ = ["KaliAgentApp", "ConsoleHooks", "TmuxBridge"]


def __getattr__(name: str):  # pragma: no cover - lazy imports keep deps optional
    if name == "TmuxBridge":
        from .tmux_bridge import TmuxBridge

        return TmuxBridge
    if name in {"KaliAgentApp", "ConsoleHooks"}:
        from .app import ConsoleHooks, KaliAgentApp

        return {"KaliAgentApp": KaliAgentApp, "ConsoleHooks": ConsoleHooks}[name]
    raise AttributeError(name)
