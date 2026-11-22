"""모든 파이프라인 단계의 공통 베이스.

feature-spec 2장: "모든 모듈은 독립 실행 가능하고, 앞 단계 JSON만 있으면
다음 단계를 다시 돌릴 수 있어야 한다." -> 각 Stage 는
- 읽는 산출물(reads)과 쓰는 산출물(writes)을 선언하고
- run(ctx) 하나로 실행되며
- 입력 산출물이 없으면 명확히 에러를 낸다.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..storage import Store


@dataclass
class PipelineContext:
    """단계 실행에 필요한 공용 상태."""

    cve_id: str
    config: Config
    store: Store
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class StageResult:
    stage: str
    ok: bool
    artifacts: list[Path] = field(default_factory=list)
    message: str = ""


class Stage(abc.ABC):
    """단계 인터페이스. CLI 서브커맨드 하나 = Stage 하나."""

    #: CLI 서브커맨드 이름 (예: "collect")
    name: str = ""
    #: 몇 주차 모듈인지 / feature-spec 모듈 ID
    module: str = ""
    #: 입력으로 요구하는 산출물 파일명들
    reads: tuple[str, ...] = ()
    #: 생성하는 산출물 파일명들
    writes: tuple[str, ...] = ()

    def check_inputs(self, ctx: PipelineContext) -> None:
        """reads 산출물이 모두 존재하는지 확인."""
        missing = [a for a in self.reads if not ctx.store.exists(a)]
        if missing:
            raise FileNotFoundError(
                f"[{self.name}] 선행 산출물 없음: {missing} "
                f"(앞 단계를 먼저 실행하세요)"
            )

    def save(self, ctx: PipelineContext, obj: Any) -> Path:
        """산출물 저장 + meta(단계 이름, 입력 해시) 기록."""
        return ctx.store.save(obj, stage=self.name, inputs=self.reads)

    @abc.abstractmethod
    def run(self, ctx: PipelineContext) -> StageResult:
        """단계 본체. 서브클래스가 구현. 시작 시 ``check_inputs`` 를 호출한다."""
        raise NotImplementedError
