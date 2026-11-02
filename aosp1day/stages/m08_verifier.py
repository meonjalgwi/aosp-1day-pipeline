"""M8. Verifier — 패치 전후 동적 검증 (2주 환경 · 7주, F-801~F-806).

입력: CVE/후보 + 테스트 템플릿
출력: verification.json + 로그

Harness(테스트 생성, F-802)는 서진 담당, 실행·판정은 TBD.
Emulator 초기화 -> APK 설치 -> 테스트 -> logcat 수집을 자동화하고,
취약 버전 vs 패치 버전 결과를 차등 판정한다.
"""

from __future__ import annotations

from ..schemas import BuildResult, RootCause, Verification
from .base import PipelineContext, Stage, StageResult


class Verifier(Stage):
    name = "verify"
    module = "M8"
    # 가설(root_cause)이 있으면 테스트 생성에 활용. 후보 직접 검증도 가능.
    reads = (RootCause.ARTIFACT,)
    writes = (Verification.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        target = ctx.params.get("target", ctx.cve_id)
        test = self.generate_test(ctx.cve_id)
        vuln = self.run_on_build(test, build="vulnerable", ctx=ctx)
        patched = self.run_on_build(test, build="patched", ctx=ctx)
        result = self.diff_verdict(target, vuln, patched)
        path = ctx.store.save(result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def reset_environment(self, ctx: PipelineContext) -> None:
        """F-801. Emulator/Cuttlefish 스냅샷 복원."""
        raise NotImplementedError

    def generate_test(self, cve_id: str):
        """F-802 (Harness). 테스트 APK / instrumentation 템플릿에
        Intent·Binder 호출 파라미터 주입. -> 서진 담당."""
        raise NotImplementedError

    def run_on_build(self, test, build: str, ctx: PipelineContext) -> BuildResult:
        """F-803. 초기화 -> APK 설치 -> 테스트 실행 -> logcat 수집 (한 명령)."""
        raise NotImplementedError

    def diff_verdict(self, target: str, vuln: BuildResult, patched: BuildResult) -> Verification:
        """F-804. 취약 vs 패치 결과 비교 (SecurityException/크래시/반환값)."""
        raise NotImplementedError

    def classify_failure(self, result: Verification) -> str:
        """F-805. 실패 원인 분류 (env/build/hypothesis/test)."""
        raise NotImplementedError

    def retry_policy(self, attempt: int) -> bool:
        """F-806(P2). 부팅 지연·flaky test 재시도."""
        raise NotImplementedError
