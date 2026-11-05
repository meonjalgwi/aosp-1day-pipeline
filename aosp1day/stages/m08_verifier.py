"""M8. Verifier — 패치 전후 동적 검증 (2주 환경 · 7주, F-801·F-803~F-806). 실행·판정 담당: TBD.

입력: test_cases.json (Harness 결과)
출력: verification.json + logs/<test_id>-<side>.logcat

빌드(취약/패치)마다: 환경 초기화 -> 공용 테스트 APK 설치(caller.apk_variant) -> 권한 grant ->
setup 명령 -> 파라미터 JSON push -> am instrument -> logcat 수집 -> teardown.
expected_* (ExpectedResult) 와 RunResult 를 필드 단위로 비교해 자동 판정한다.
P0 target 은 CVE ID 만 (후보 검증은 P1).
기기는 Cuttlefish 1차, 2주차 성공 기준 미달 시 Emulator (최종적으로 하나만 지원).
"""

from __future__ import annotations

from ..schemas import BuildInfo, ExpectedResult, RunResult, TestCase, TestCases, TestVerdict, Verification
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
        """config.device.vulnerable_image / patched_image (+ swap_modules) → BuildInfo.

        env_image(환경 확인용 최신 CI 이미지)는 재현에 쓰지 않는다. fingerprint 는 부팅 후 채움.
        """
        raise NotImplementedError

    def reset_environment(self, build: BuildInfo, ctx: PipelineContext) -> None:
        """F-801. Cuttlefish 재시작 / Emulator 스냅샷 복원."""
        raise NotImplementedError

    def run_on_build(self, test: TestCase, build: BuildInfo, ctx: PipelineContext) -> RunResult:
        """F-803. reset -> install(caller.apk_variant) -> grant -> setup -> push params
        -> am instrument -> logcat 저장·근거 줄 추출 -> teardown."""
        raise NotImplementedError

    def matches(self, expected: ExpectedResult, actual: RunResult, logcat: str = "") -> bool:
        """기대 결과 비교: outcome 일치 + (지정된 경우) exception_type·return_value·log_regex 일치."""
        import re
        if expected.outcome != actual.outcome:
            return False
        if expected.exception_type and expected.exception_type != actual.exception_type:
            return False
        if expected.log_regex and not re.search(expected.log_regex, logcat):
            return False
        # return_value(ValueSpec) 비교는 구현 시 추가
        return True

    def diff_verdict(self, test: TestCase, vuln: RunResult, patched: RunResult,
                     vuln_log: str = "", patched_log: str = "") -> TestVerdict:
        """F-804. 취약 빌드가 expected_vulnerable, 패치 빌드가 expected_patched 와 모두 맞으면 reproduced."""
        if "timeout" in (vuln.outcome, patched.outcome) or not vuln.outcome or not patched.outcome:
            verdict = "error"
        elif self.matches(test.expected_vulnerable, vuln, vuln_log) and self.matches(test.expected_patched, patched, patched_log):
            verdict = "reproduced"
        else:
            verdict = "not_reproduced"
        return TestVerdict(test_id=test.id, vulnerable=vuln, patched=patched, verdict=verdict)

    def classify_failure(self, verdict: TestVerdict) -> str:
        """F-805. 실패 원인 분류 (env/build/hypothesis/test)."""
        raise NotImplementedError

    def retry_policy(self, attempt: int) -> bool:
        """F-806(P2). 부팅 지연·flaky test 재시도."""
        raise NotImplementedError
