"""산출물 저장소: ``output/<CVE-ID>/*.json`` 읽기/쓰기.

모든 모듈은 파일 경로를 직접 다루지 않고 이 레이어를 거친다.
- dataclass <-> JSON 직렬화 (schemas.FIELD_ALIASES 로 "class" 등 예약어 키 매핑)
- 중첩 dataclass / 리스트 복원
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Type, TypeVar, get_args, get_origin, get_type_hints

from . import schemas

T = TypeVar("T")


def _py_to_json_key(name: str) -> str:
    return schemas.FIELD_ALIASES.get(name, name)


def _json_to_py_key(name: str) -> str:
    rev = {v: k for k, v in schemas.FIELD_ALIASES.items()}
    return rev.get(name, name)


def to_dict(obj: Any) -> Any:
    """dataclass 트리를 JSON 호환 dict 로 변환 (키 별칭 적용)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {}
        for f in dataclasses.fields(obj):
            out[_py_to_json_key(f.name)] = to_dict(getattr(obj, f.name))
        return out
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    return obj


def from_dict(cls: Type[T], data: dict) -> T:
    """JSON dict 를 dataclass 트리로 복원.

    skeleton 수준의 복원기. 중첩 dataclass 와 list[dataclass] 만 처리한다.
    """
    if not dataclasses.is_dataclass(cls):
        return data  # type: ignore[return-value]
    kwargs: dict[str, Any] = {}
    # from __future__ import annotations 때문에 f.type 는 문자열이므로 실제 타입으로 해석
    type_hints = get_type_hints(cls)
    for f in dataclasses.fields(cls):
        json_key = _py_to_json_key(f.name)
        if json_key not in data:
            continue
        kwargs[f.name] = _coerce(type_hints[f.name], data[json_key])
    return cls(**kwargs)  # type: ignore[call-arg]


def _coerce(hint: Any, value: Any) -> Any:
    origin = get_origin(hint)
    if dataclasses.is_dataclass(hint) and isinstance(value, dict):
        return from_dict(hint, value)
    if origin in (list, tuple) and isinstance(value, list):
        (inner,) = get_args(hint) or (Any,)
        return [_coerce(inner, v) for v in value]
    return value


class Store:
    """CVE 하나의 산출물 디렉터리(``output/<CVE-ID>/``) 핸들."""

    def __init__(self, output_root: Path, cve_id: str) -> None:
        self.dir = Path(output_root) / cve_id
        self.cve_id = cve_id

    def path(self, artifact: str) -> Path:
        return self.dir / artifact

    def exists(self, artifact: str) -> bool:
        return self.path(artifact).is_file()

    def save(self, obj: Any) -> Path:
        """dataclass 인스턴스를 ``obj.ARTIFACT`` 파일명으로 저장."""
        artifact = getattr(obj, "ARTIFACT")
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self.path(artifact)
        p.write_text(json.dumps(to_dict(obj), indent=2, ensure_ascii=False))
        return p

    def load(self, cls: Type[T]) -> T:
        """``cls.ARTIFACT`` 파일을 읽어 dataclass 로 복원."""
        artifact = getattr(cls, "ARTIFACT")
        raw = json.loads(self.path(artifact).read_text())
        return from_dict(cls, raw)

    def save_text(self, name: str, content: str) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self.path(name)
        p.write_text(content)
        return p
