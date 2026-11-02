"""비동기 작업 큐 (F-1002).

분석은 오래 걸리므로 백그라운드 작업으로 돌리고, 대시보드(D-2)는 진행 상태를
폴링/웹소켓으로 갱신한다. skeleton 단계에서는 인터페이스만 정의한다.

TODO: 실제 구현 시 Celery/RQ 또는 간단한 asyncio 작업 테이블 중 선택.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


# 대시보드 D-2 진행률 표시용 단계 라벨
STAGES = ("collect", "analyze", "binder-path", "root-cause",
          "pattern", "scan", "prioritize", "verify", "report")


@dataclass
class Job:
    cve_id: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: JobStatus = JobStatus.QUEUED
    current_stage: str | None = None
    error: str | None = None


class JobQueue:
    """작업 등록·상태 조회 인터페이스."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def enqueue(self, cve_id: str, start: str | None = None, params: dict | None = None) -> Job:
        """새 분석 작업 등록 (POST /api/analyses)."""
        raise NotImplementedError

    def get(self, cve_id: str) -> Job | None:
        """작업 상태 조회 (GET /api/analyses/{cve_id})."""
        raise NotImplementedError

    def list(self) -> list[Job]:
        raise NotImplementedError
