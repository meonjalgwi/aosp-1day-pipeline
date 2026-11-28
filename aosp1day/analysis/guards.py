"""Guard 사전(config/guard_dictionary.json) 로드와 호출 하나의 Guard 유형 판정."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .java_ast import Call

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "guard_dictionary.json"


@dataclass
class GuardDictionary:
    types: dict[str, dict]
    priority: list[str]
    ignore_calls: set[str]
    ignore_receivers: set[str]

    @classmethod
    def load(cls, path: Path | str | None = None) -> "GuardDictionary":
        data = json.loads(Path(path or DEFAULT_PATH).read_text(encoding="utf-8"))
        return cls(types=data["types"], priority=data["priority"],
                   ignore_calls=set(data.get("ignore_calls", [])),
                   ignore_receivers=set(data.get("ignore_receivers", [])))

    def match(self, call: Call) -> list[str]:
        """호출 이름이 사전에 있으면 Guard 유형 목록. condition_apis 는 조건식 안일 때만."""
        out = []
        for t, spec in self.types.items():
            if call.name in spec.get("apis", ()):
                out.append(t)
            elif call.in_condition and call.name in spec.get("condition_apis", ()):
                out.append(t)
        return out

    def is_guard_api(self, name: str) -> bool:
        return any(name in s.get("apis", ()) or name in s.get("condition_apis", ())
                   for s in self.types.values())

    def is_identity_only(self, t: str) -> bool:
        return bool(self.types.get(t, {}).get("identity_only"))

    def apply_suppression(self, types: set[str]) -> set[str]:
        """같은 호출 지점에서 상위 유형이 하위 유형을 덮는다 (예: UID_PACKAGE_BINDING > CALLER_UID)."""
        out = set(types)
        for t in types:
            out -= set(self.types.get(t, {}).get("suppresses", ()))
        return out

    def is_noise(self, call: Call) -> bool:
        root = call.receiver.split(".")[0] if call.receiver else ""
        return call.name in self.ignore_calls or root in self.ignore_receivers

    def order(self, types) -> list[str]:
        rank = {t: i for i, t in enumerate(self.priority)}
        return sorted(types, key=lambda t: rank.get(t, len(rank)))
