"""LLM 추상화 (M4). 특정 업체 SDK에 파이프라인이 묶이지 않도록 인터페이스만 노출한다.

키 관리 원칙 (feature-spec 5장)
- API 키는 환경변수로만 받는다. config.yaml 에는 provider·model·환경변수 이름만 기록.
- 키를 결과 JSON·로그·프롬프트 기록·대시보드에 절대 남기지 않는다.
- 결과에는 provider·model·prompt hash 만 기록한다 (``schemas.LlmProvenance``).
"""

from __future__ import annotations

import abc
import hashlib
from typing import Any

from .config import LlmConfig
from .schemas import LlmProvenance


class LlmClient(abc.ABC):
    def __init__(self, config: LlmConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def generate_structured(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """JSON schema 를 따르는 응답(dict)을 반환. 스키마 위반 시 예외."""
        raise NotImplementedError

    def provenance(self, prompt: str, prompt_path: str = "") -> LlmProvenance:
        return LlmProvenance(
            provider=self.config.provider,
            model=self.config.model,
            temperature=self.config.temperature,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
            prompt_path=prompt_path,
        )


def get_client(config: LlmConfig) -> LlmClient:
    """config.provider 에 맞는 구현체 반환. 구현체는 llm_providers/ 에 추가 (예: anthropic, openai)."""
    raise NotImplementedError(f"LLM provider 미구현: {config.provider}")
