"""산출물 저장소: ``output/<CVE-ID>/*.json`` 읽기/쓰기.

모든 모듈은 파일 경로를 직접 다루지 않고 이 레이어를 거친다.
- dataclass <-> JSON 직렬화 (schemas.FIELD_ALIASES 로 "class" 등 예약어 키 매핑)
- 중첩 dataclass / 리스트 복원
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import types
import typing
from datetime import datetime, timezone
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
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


def from_dict(cls: Type[T], data: dict) -> T:
    """JSON dict 를 dataclass 트리로 복원.

    중첩 dataclass, list[...], dict[str, ...], Optional[...] 를 처리한다.
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
    if value is None:
        return None
    origin = get_origin(hint)
    if origin in (typing.Union, types.UnionType):          # Optional[X]
        inner = [a for a in get_args(hint) if a is not type(None)]
        return _coerce(inner[0], value) if len(inner) == 1 else value
    if dataclasses.is_dataclass(hint) and isinstance(value, dict):
        return from_dict(hint, value)
    if origin in (list, tuple) and isinstance(value, list):
        (inner,) = get_args(hint) or (Any,)
        return [_coerce(inner, v) for v in value]
    if origin is dict and isinstance(value, dict):
        _, inner = get_args(hint) or (Any, Any)
        return {k: _coerce(inner, v) for k, v in value.items()}
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Store:
    """CVE 하나의 산출물 디렉터리(``output/<CVE-ID>/``) 핸들."""

    def __init__(self, output_root: Path, cve_id: str) -> None:
        self.dir = Path(output_root) / cve_id
        self.cve_id = cve_id

    def path(self, artifact: str) -> Path:
        return self.dir / artifact

    def exists(self, artifact: str) -> bool:
        return self.path(artifact).is_file()

    def save(self, obj: Any, stage: str = "", inputs: tuple[str, ...] = ()) -> Path:
        """dataclass 인스턴스를 ``obj.ARTIFACT`` 파일명으로 저장.

        ``meta`` 필드가 있으면 생성 시각·단계·입력 산출물 해시를 채운다 (재현성).
        """
        artifact = getattr(obj, "ARTIFACT")
        meta = getattr(obj, "meta", None)
        if meta is not None:
            from . import __version__
            meta.generated_at = datetime.now(timezone.utc).isoformat()
            meta.tool_version = __version__
            meta.stage = stage or meta.stage
            meta.inputs = {a: sha256_file(self.path(a)) for a in inputs if self.exists(a)}
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
        p = self.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p
