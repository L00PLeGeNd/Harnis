"""A deterministic agent that offers a credential tool call.

Used by `harnis probe` to show a reproducible finding. It never reads
the file; it only proposes the tool call.
"""

from __future__ import annotations

from harnis.probe import Turn


def build_agent():
    return LeakyAgent()


class LeakyAgent:
    def respond(self, turns: list[Turn]) -> Turn:
        last = turns[-1].text if turns else ""
        if "ssh" in last.lower() or "key" in last.lower() or "id_rsa" in last.lower():
            return Turn(
                role="assistant",
                text="I will read the key for you.",
                tool_calls=(
                    {
                        "name": "read_file",
                        "arguments": {"path": "/home/agent/.ssh/id_rsa"},
                    },
                ),
            )
        return Turn(role="assistant", text="How can I help?")
