"""M1. Collector — CVE/패치 수집 (2주차, F-101~F-106).

입력: CVE ID 또는 AOSP 패치 커밋 URL/해시
출력: cve.json + patches/<hash>.diff + src/<hash>/{before,after}/<변경 파일>
"""

from __future__ import annotations

from ..schemas import CveRecord, PatchCommit
from ..storage import Store
from .base import PipelineContext, Stage, StageResult


class Collector(Stage):
    name = "collect"
    module = "M1"
    reads = ()
    writes = (CveRecord.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        source = ctx.params.get("source") or ctx.cve_id
        if self.is_cached(ctx):
            return StageResult(self.name, ok=True, artifacts=[ctx.store.path(CveRecord.ARTIFACT)], message="cached")
        record = self.collect(source)
        for commit in record.patch_commits:
            self.save_sources(commit, ctx.store)     # diff_path / before_dir / after_dir 채움
        path = self.save(ctx, record)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def collect(self, source: str) -> CveRecord:
        """F-101. CVE ID 또는 커밋 URL/해시를 받아 CveRecord 조립 (F-102·F-103 호출)."""
        raise NotImplementedError

    def parse_security_bulletin(self, cve_id: str) -> dict:
        """F-102. Android Security Bulletin 에서 컴포넌트·심각도·유형·영향 버전·패치 링크."""
        raise NotImplementedError

    def fetch_patch_metadata(self, commit_url: str) -> PatchCommit:
        """F-103. 커밋 메시지·작성일·브랜치·부모 커밋·변경 파일 목록."""
        raise NotImplementedError

    def save_sources(self, commit: PatchCommit, store: Store) -> None:
        """F-104. diff 와 변경 파일의 패치 전(parent)/후(commit) 원본을 저장하고 경로를 commit 에 기록.

        저장 위치:
          patches/<hash>.diff
          src/<hash>/before/<frameworks/base 기준 경로>   (parent 리비전)
          src/<hash>/after/<frameworks/base 기준 경로>    (패치 커밋 리비전)
        경로는 output/<CVE-ID>/ 기준 상대 경로로 기록한다.
        """
        raise NotImplementedError

    def handle_edge_cases(self, source: str, record: CveRecord) -> None:
        """F-105. 잘못된 링크, 비공개 버그, 여러 브랜치에 나뉜 패치 → record.notes 에 기록."""
        raise NotImplementedError

    def is_cached(self, ctx: PipelineContext) -> bool:
        """F-106. cve.json 과, 그 안의 모든 커밋의 diff·패치 전/후 소스가 실제로 있을 때만 캐시 사용.

        중간에 끊긴 수집(cve.json 만 있고 diff/소스가 없는 경우)은 캐시로 보지 않는다. params.force 로 무시.
        """
        if ctx.params.get("force") or not ctx.store.exists(CveRecord.ARTIFACT):
            return False
        record = ctx.store.load(CveRecord)
        if not record.patch_commits:
            return False
        for c in record.patch_commits:
            paths = [c.diff_path, c.before_dir, c.after_dir]
            if not all(paths):
                return False
            diff, before, after = (ctx.store.dir / p for p in paths)
            if not (diff.is_file() and before.is_dir() and after.is_dir()):
                return False
            if any(not (after / f).exists() and not (before / f).exists() for f in c.changed_files):
                return False   # 변경 파일이 전/후 어디에도 없음 (추가·삭제 파일은 한쪽에만 있음)
        return True
