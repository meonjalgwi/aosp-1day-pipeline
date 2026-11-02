"""설정 로더 (F-1005).

AOSP 경로, LLM 모델, Emulator 설정 등을 ``config.yaml`` 로 관리한다.
API 키는 리포에 커밋하지 않고 환경변수로 받는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LlmConfig:
    provider: str = "anthropic"
    model: str = "claude-opus-4-8"
    temperature: float = 0.0          # 재현성: temperature 고정
    api_key_env: str = "ANTHROPIC_API_KEY"

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)


@dataclass
class EmulatorConfig:
    kind: str = "emulator"            # emulator | cuttlefish
    snapshot: str = "clean"
    boot_timeout_sec: int = 120


@dataclass
class Config:
    aosp_root: Path = Path("aosp/frameworks/base")
    output_root: Path = Path("output")
    rules_dir: Path = Path("rules")
    llm: LlmConfig = field(default_factory=LlmConfig)
    emulator: EmulatorConfig = field(default_factory=EmulatorConfig)

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        """config.yaml 로드. 없으면 기본값.

        TODO: PyYAML 로 실제 파싱 (현재는 skeleton 기본값 반환).
        """
        p = Path(path)
        if not p.is_file():
            return cls()
        raise NotImplementedError("config.yaml 파싱 (PyYAML) 미구현")
