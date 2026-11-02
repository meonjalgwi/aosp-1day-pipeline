"""오케스트레이터.

CVE 한 건에 대해 M1 -> M9 단계를 순서대로 실행한다.
- 각 단계는 앞 단계 JSON 산출물만 있으면 독립 실행 가능 (feature-spec 2장)
- ``start`` 로 특정 단계부터 재실행 (F-1003 단계별 재실행)
- 대시보드 Backend(M10)는 이 Pipeline 을 비동기 작업으로 감싼다 (jobs.py)
"""

from __future__ import annotations

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
        return all(r.ok for r in self.results)


class Pipeline:
    def __init__(self, config: Config) -> None:
        self.config = config

    def context(self, cve_id: str, params: dict | None = None) -> PipelineContext:
        store = Store(self.config.output_root, cve_id)
        return PipelineContext(cve_id=cve_id, config=self.config, store=store, params=params or {})

    def run_stage(self, stage_name: str, cve_id: str, params: dict | None = None) -> StageResult:
        """단일 단계 실행 (CLI 서브커맨드 하나에 대응)."""
        stage_cls = REGISTRY[stage_name]
        ctx = self.context(cve_id, params)
        return stage_cls().run(ctx)

    def run_all(self, cve_id: str, start: str | None = None, params: dict | None = None) -> PipelineRun:
        """M1 -> M9 전체 실행. ``start`` 지정 시 그 단계부터.

        TODO: 단계 실패 시 중단/계속 정책, 진행 상태 콜백(대시보드 D-2 진행률).
        """
        run = PipelineRun(cve_id=cve_id)
        started = start is None
        for stage_cls in PIPELINE:
            if not started:
                started = stage_cls.name == start
                if not started:
                    continue
            result = self.run_stage(stage_cls.name, cve_id, params)
            run.results.append(result)
            if not result.ok:
                break
        return run
