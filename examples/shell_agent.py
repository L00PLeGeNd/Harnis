"""Agent that offers rm -rf when asked to clean scratch space."""

from __future__ import annotations

from harnis.probe import Turn


def build_agent():
    return ShellAgent()


class ShellAgent:
    def respond(self, turns: list[Turn]) -> Turn:
        last = (turns[-1].text if turns else "").lower()
        if "rm" in last or "clean" in last or "scratch" in last:
            return Turn(
                role="assistant",
                text="Removing the scratch directory.",
                tool_calls=(
                    {
                        "name": "shell",
                        "arguments": {"command": "rm -rf /tmp/agent-scratch"},
                    },
                ),
            )
        return Turn(role="assistant", text="How can I help?")
