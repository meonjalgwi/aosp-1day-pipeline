"""M8. Verifier — 패치 전후 동적 검증 (2주 환경 · 7주, F-801·F-803~F-806). 실행·판정 담당: TBD.

입력: test_cases.json (Harness 결과)
출력: verification.json + logs/<test_id>-<side>.logcat

환경 초기화 -> APK 설치 -> 테스트 -> logcat 수집을 취약/패치 빌드에서 각각 돌리고 차등 판정한다.
기기는 Cuttlefish 1차, 2주차 성공 기준 미달 시 Emulator (최종적으로 하나만 지원).
"""

from __future__ import annotations

from ..schemas import BuildInfo, RunResult, TestCase, TestCases, TestVerdict, Verification
from .base import PipelineContext, Stage, StageResult


class Verifier(Stage):
    name = "verify"
    module = "M8"
    reads = (TestCases.ARTIFACT,)
    writes = (Verification.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        self.check_inputs(ctx)
        tests = ctx.store.load(TestCases)
        result = Verification(cve_id=tests.cve_id, target=ctx.params.get("target", tests.cve_id))
        for test in tests.tests:
            vuln = self.run_on_build(test, self.build_info("vulnerable", ctx), ctx)
            patched = self.run_on_build(test, self.build_info("patched", ctx), ctx)
            result.results.append(self.diff_verdict(test, vuln, patched))
        result.verdict = "reproduced" if any(r.verdict == "reproduced" for r in result.results) else (
            "error" if any(r.verdict == "error" for r in result.results) else "not_reproduced")
        path = self.save(ctx, result)
        return StageResult(self.name, ok=True, artifacts=[path])

    # --- 세부 기능 ---------------------------------------------------------

    def build_info(self, side: str, ctx: PipelineContext) -> BuildInfo:
        """config 의 취약/패치 이미지 정보 → BuildInfo (fingerprint 는 부팅 후 채움)."""
        raise NotImplementedError

    def reset_environment(self, build: BuildInfo, ctx: PipelineContext) -> None:
        """F-801. Cuttlefish 재시작 / Emulator 스냅샷 복원."""
        raise NotImplementedError

    def run_on_build(self, test: TestCase, build: BuildInfo, ctx: PipelineContext) -> RunResult:
        """F-803. 초기화 -> APK 설치 -> 테스트 실행 -> logcat 저장, 판정 근거 줄 추출."""
        raise NotImplementedError

    def diff_verdict(self, test: TestCase, vuln: RunResult, patched: RunResult) -> TestVerdict:
        """F-804. test.expected_* 와 실제 outcome 비교 → reproduced / not_reproduced / error."""
        raise NotImplementedError

    def classify_failure(self, verdict: TestVerdict) -> str:
        """F-805. 실패 원인 분류 (env/build/hypothesis/test)."""
        raise NotImplementedError

    def retry_policy(self, attempt: int) -> bool:
        """F-806(P2). 부팅 지연·flaky test 재시도."""
        raise NotImplementedError
