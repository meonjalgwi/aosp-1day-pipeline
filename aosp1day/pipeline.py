"""오케스트레이터.

CVE 한 건에 대해 PIPELINE 단계를 순서대로 실행한다.
- 각 단계는 앞 단계 JSON 산출물만 있으면 독립 실행 가능 (feature-spec 2장)
- ``start`` 로 특정 단계부터 재실행
- 단계가 실패해도 중단하지 않는다. 다음 단계의 입력(reads)이 없으면 그 단계는 "건너뜀"으로 기록.
  → 예: Scanner 가 실패해도 기준선 검증(Harness·Verifier)은 돈다.
- 단계에서 예외가 나면 ok=False 결과로 기록 (실패 단계·에러를 logs/ 에 남김)
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field

from .config import Config
from .stages import PIPELINE, REGISTRY, PipelineContext, StageResult
from .storage import Store


@dataclass
class PipelineRun:
    cve_id: str
    results: list[StageResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.results) and all(r.ok for r in self.results)


class Pipeline:
    def __init__(self, config: Config) -> None:
        self.config = config

    def context(self, cve_id: str, params: dict | None = None) -> PipelineContext:
        store = Store(self.config.output_root, cve_id)
        return PipelineContext(cve_id=cve_id, config=self.config, store=store, params=params or {})

    def run_stage(self, stage_name: str, cve_id: str, params: dict | None = None) -> StageResult:
        """단일 단계 실행 (CLI 서브커맨드 하나에 대응). 예외는 ok=False 로 변환."""
        stage_cls = REGISTRY[stage_name]
        ctx = self.context(cve_id, params)
        try:
            return stage_cls().run(ctx)
        except NotImplementedError as e:
            return StageResult(stage_name, ok=False, message=f"미구현: {str(e) or stage_cls.__name__}")
        except Exception as e:  # noqa: BLE001 — 단계 실패를 결과로 남긴다
            ctx.store.save_text(f"logs/{stage_name}.error.txt", traceback.format_exc())
            return StageResult(stage_name, ok=False, message=f"{type(e).__name__}: {e}")

    def run_all(self, cve_id: str, start: str | None = None, params: dict | None = None) -> PipelineRun:
        """PIPELINE 전체 실행. ``start`` 지정 시 그 단계부터."""
        if start is not None and start not in REGISTRY:
            raise ValueError(f"알 수 없는 단계: {start}")
        run = PipelineRun(cve_id=cve_id)
        store = Store(self.config.output_root, cve_id)
        started = start is None
        for stage_cls in PIPELINE:
            started = started or stage_cls.name == start
            if not started:
                continue
            missing = [a for a in stage_cls.reads if not store.exists(a)]
            if missing:
                run.results.append(StageResult(stage_cls.name, ok=False, message=f"건너뜀: 선행 산출물 없음 {missing}"))
                continue
            run.results.append(self.run_stage(stage_cls.name, cve_id, params))
        return run
