"""KaliAgent - autonomous security-operations agent for Kali Linux.

The package is split into small, single-purpose modules:

* :mod:`agent.config`          - first-run API key handling and persistent config
* :mod:`agent.llm`             - Gemini client + manual function-calling loop
* :mod:`agent.system_prompt`   - the system instruction given to the model
* :mod:`agent.tools`           - tool declarations + dispatch table
* :mod:`agent.tool_registry`   - Kali tool scan / search / help / install
* :mod:`agent.kali_categories` - category mapping for Kali packages
* :mod:`agent.executor`        - command runner (live stream, timeout, sudo)
* :mod:`agent.safety`          - destructive-command filter + scope check
* :mod:`agent.memory`          - session context and findings
* :mod:`agent.logger`          - JSONL session logs
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
