"""Session budget: stop thrashing edits, runaway calls, and path wandering."""

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
_PATH_TOOLS = _WRITE_TOOLS | frozenset({
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "read",
    "open_file",
    "cat",
    "fetch_file",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "search_files",
    "get_file_info",
    "move_file",
})


@dataclass
class EditBudget:
    """Count near-identical writes, tool calls, and unique paths in one session."""

    empty_edit_limit: int = 5
    max_tool_calls: int | None = None
    max_unique_paths: int | None = None
    _streak: dict[str, tuple[str, int]] = field(default_factory=dict)
    _calls: int = 0
    _paths: set[str] = field(default_factory=set)

    @classmethod
    def from_rules(cls, rules: Rules) -> EditBudget:
        return cls(
            empty_edit_limit=rules.empty_edit_limit,
            max_tool_calls=rules.max_tool_calls,
            max_unique_paths=rules.max_unique_paths,
        )

    def judge(self, name: str, arguments: dict) -> Decision | None:
        self._calls += 1
        if self.max_tool_calls is not None and self._calls > self.max_tool_calls:
            return Decision(
                False,
                "no-tool-budget",
                f"exceed the tool-call budget ({self._calls}/{self.max_tool_calls})",
            )
        path_hit = _path_target(name, arguments)
        if path_hit is not None:
            key = path_hit.replace("\\", "/").casefold()
            if key not in self._paths:
                if (
                    self.max_unique_paths is not None
                    and len(self._paths) >= self.max_unique_paths
                ):
                    return Decision(
                        False,
                        "no-path-wander",
                        f"open a new path after {self.max_unique_paths} distinct paths",
                    )
                self._paths.add(key)
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
            f"thrash {path} {count} times with no substantive change (limit {self.empty_edit_limit})",
        )

    def to_dict(self) -> dict:
        return {
            "empty_edit_limit": self.empty_edit_limit,
            "max_tool_calls": self.max_tool_calls,
            "max_unique_paths": self.max_unique_paths,
            "calls": self._calls,
            "paths": sorted(self._paths),
            "streak": {key: [finger, count] for key, (finger, count) in self._streak.items()},
        }

    @classmethod
    def from_dict(cls, data: dict, rules: Rules) -> EditBudget:
        budget = cls.from_rules(rules)
        budget._calls = int(data.get("calls") or 0)
        paths = data.get("paths") or []
        if isinstance(paths, list):
            budget._paths = {str(item) for item in paths}
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


def _path_target(name: str, arguments: dict) -> str | None:
    normalized = name.strip().lower().replace("-", "_")
    if normalized not in _PATH_TOOLS:
        return None
    if not isinstance(arguments, dict):
        return None
    for key in ("path", "file", "uri", "file_path", "source", "destination", "dest"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    paths = arguments.get("paths")
    if isinstance(paths, list):
        for item in paths:
            if isinstance(item, str) and item.strip():
                return item
    return None


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
