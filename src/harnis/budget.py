"""Session budget: stop thrashing edits and runaway tool loops."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from harnis.policy import Decision, Rules

_WRITE_TOOLS = frozenset({
    "write_file",
    "edit_file",
    "write",
    "save_file",
})


@dataclass
class EditBudget:
    """Count near-identical writes and total tools/call within one session."""

    empty_edit_limit: int = 5
    max_tool_calls: int | None = None
    _streak: dict[str, tuple[str, int]] = field(default_factory=dict)
    _calls: int = 0

    @classmethod
    def from_rules(cls, rules: Rules) -> EditBudget:
        return cls(
            empty_edit_limit=rules.empty_edit_limit,
            max_tool_calls=rules.max_tool_calls,
        )

    def judge(self, name: str, arguments: dict) -> Decision | None:
        self._calls += 1
        if self.max_tool_calls is not None and self._calls > self.max_tool_calls:
            return Decision(
                False,
                "no-tool-budget",
                f"exceed the tool-call budget ({self.max_tool_calls})",
            )
        path, content = _write_target(name, arguments)
        if path is None or content is None:
            return None
        key = path.replace("\\", "/").casefold()
        fingerprint = _normalize(content)
        previous = self._streak.get(key)
        if previous is None or previous[0] != fingerprint:
            self._streak[key] = (fingerprint, 1)
            return None
        count = previous[1] + 1
        self._streak[key] = (fingerprint, count)
        if count < self.empty_edit_limit:
            return None
        return Decision(
            False,
            "no-edit-thrash",
            f"thrash {path} {count} times with no substantive change",
        )

    def to_dict(self) -> dict:
        return {
            "empty_edit_limit": self.empty_edit_limit,
            "max_tool_calls": self.max_tool_calls,
            "calls": self._calls,
            "streak": {key: [finger, count] for key, (finger, count) in self._streak.items()},
        }

    @classmethod
    def from_dict(cls, data: dict, rules: Rules) -> EditBudget:
        budget = cls.from_rules(rules)
        budget._calls = int(data.get("calls") or 0)
        streak = data.get("streak") or {}
        if isinstance(streak, dict):
            loaded: dict[str, tuple[str, int]] = {}
            for key, value in streak.items():
                if isinstance(value, (list, tuple)) and len(value) == 2:
                    loaded[str(key)] = (str(value[0]), int(value[1]))
            budget._streak = loaded
        return budget

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict()), encoding="utf-8")

    @classmethod
    def load(cls, path: Path, rules: Rules) -> EditBudget:
        if not path.is_file():
            return cls.from_rules(rules)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls.from_rules(rules)
        if not isinstance(data, dict):
            return cls.from_rules(rules)
        return cls.from_dict(data, rules)


def _write_target(name: str, arguments: dict) -> tuple[str | None, str | None]:
    normalized = name.strip().lower().replace("-", "_")
    if normalized not in _WRITE_TOOLS:
        return None, None
    if not isinstance(arguments, dict):
        return None, None
    path = arguments.get("path") or arguments.get("file") or arguments.get("uri")
    if not isinstance(path, str) or not path.strip():
        return None, None
    content = _content(arguments)
    if content is None:
        return None, None
    return path, content


def _content(arguments: dict) -> str | None:
    for key in ("content", "text", "contents", "new_string", "newString", "new_text"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    return None


def _normalize(text: str) -> str:
    return " ".join(text.split())
