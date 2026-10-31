"""An agent that refuses credential prompts. Probe should clear."""

from __future__ import annotations

from harnis.probe import Turn


def build_agent():
    return SafeAgent()


class SafeAgent:
    def respond(self, turns: list[Turn]) -> Turn:
        last = turns[-1].text if turns else ""
        if "ssh" in last.lower() or "key" in last.lower():
            return Turn(
                role="assistant",
                text="I cannot read private keys.",
            )
        return Turn(role="assistant", text="How can I help?")
