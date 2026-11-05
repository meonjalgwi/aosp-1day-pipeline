"""M8. Verifier — Harness: 테스트 준비 (F-807 P0 / F-802 P1). 담당: 서진.

출력: test_cases.json (+ tests/<test_id>.json 파라미터 파일)

P0 (F-807) — 사람이 작성한 기준선 테스트
  ``baselines/<CVE-ID>.tests.json`` (TestCases 형식)이 있으면 형식을 검증하고 그대로 내보낸다.
  root_cause.json / call_path.json 이 없어도 동작한다.

P1 (F-802) — 자동 생성
  위 파일이 없을 때만 root_cause.json 의 hypotheses + call_path.json 의 진입점으로 TestCase 를 만든다.
  만들지 못한 가설은 TestCases.skipped 에 이유와 함께 남긴다 (조용히 빠지지 않게).

테스트는 테스트마다 APK 를 빌드하지 않는다. 미리 빌드한 공용 instrumentation APK
(config.device.test_apks) 가 파라미터 JSON 을 읽어 ValueSpec 대로 인자를 조립해 호출한다.
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import (
    OUTCOMES,
    CallPath,
    CallPathEntry,
    Claim,
    RootCause,
    SkippedHypothesis,
    TestCase,
    TestCases,
    ValueSpec,
)
from ..storage import Store, from_dict, to_dict
from .base import PipelineContext, Stage, StageResult

# P0 ValueSpec 에서 지원하는 type (공용 APK 가 조립할 수 있는 것)
P0_VALUE_TYPES = ("null", "bool", "int", "long", "float", "string", "array", "bundle", "intent", "ref")


class Harness(Stage):
    name = "harness"
    module = "M8"
    reads = ()          # P0 수동 경로는 선행 산출물이 필요 없다. 자동 경로는 run() 안에서 확인.
    writes = (TestCases.ARTIFACT,)

    def run(self, ctx: PipelineContext) -> StageResult:
        manual = self.manual_tests_path(ctx)
        if manual.is_file():
            result = self.load_manual(manual, ctx.cve_id)          # F-807 (P0)
        else:
            result = self.generate(ctx)                            # F-802 (P1)
        errors = [e for t in result.tests for e in self.validate(t)]
        if errors:
            return StageResult(self.name, ok=False, message="TestCase 검증 실패: " + "; ".join(errors))
        for test in result.tests:
            test.params_path = str(self.write_params(test, ctx.store))
        path = ctx.store.save(result, stage=self.name, inputs=())
        return StageResult(self.name, ok=True, artifacts=[path], message=f"{len(result.tests)} tests, {len(result.skipped)} skipped")

    # --- P0: 수동 기준선 테스트 -------------------------------------------

    def manual_tests_path(self, ctx: PipelineContext) -> Path:
        return Path(ctx.params.get("tests") or ctx.config.baselines_dir / f"{ctx.cve_id}.tests.json")

    def load_manual(self, path: Path, cve_id: str) -> TestCases:
        import json
        result = from_dict(TestCases, json.loads(path.read_text()))
        result.cve_id = result.cve_id or cve_id
        for t in result.tests:
            t.source = "manual"
        return result

    def validate(self, test: TestCase) -> list[str]:
        """필수 필드, 지원 ValueSpec type, outcome 값 목록 검사. 문제 목록 반환 (비면 통과)."""
        errs: list[str] = []
        if not test.id:
            errs.append("id 없음")
        if not test.calls:
            errs.append(f"{test.id}: calls 없음")
        for exp_name in ("expected_vulnerable", "expected_patched"):
            outcome = getattr(test, exp_name).outcome
            if outcome not in OUTCOMES:
                errs.append(f"{test.id}: {exp_name}.outcome={outcome!r} (허용: {', '.join(OUTCOMES)})")
        for call in test.calls:
            for arg in call.args:
                errs.extend(f"{test.id}/{call.id}: {e}" for e in self._check_value(arg))
        return errs

    def _check_value(self, v: ValueSpec) -> list[str]:
        if v.type not in P0_VALUE_TYPES:
            return [f"ValueSpec type {v.type!r} 는 P0 미지원"]
        out: list[str] = []
        for child in (*v.items, *v.entries.values()):
            out.extend(self._check_value(child))
        return out

    def write_params(self, test: TestCase, store: Store) -> Path:
        """공용 APK 가 읽을 파라미터 JSON (caller 제외한 calls·expected) 저장 → 기기에 push 됨."""
        import json
        payload = {"id": test.id, "template": test.template, "calls": to_dict(test.calls)}
        return store.save_text(f"tests/{test.id}.json", json.dumps(payload, indent=2, ensure_ascii=False))

    # --- P1: 자동 생성 ----------------------------------------------------

    def generate(self, ctx: PipelineContext) -> TestCases:
        """F-802. hypotheses → TestCase. 못 만든 가설은 skipped 에 기록."""
        missing = [a for a in (RootCause.ARTIFACT, CallPath.ARTIFACT) if not ctx.store.exists(a)]
        if missing:
            raise FileNotFoundError(
                f"[harness] {self.manual_tests_path(ctx)} 도 없고 자동 생성용 산출물도 없음: {missing}")
        root_cause = ctx.store.load(RootCause)
        call_path = ctx.store.load(CallPath)
        result = TestCases(cve_id=root_cause.cve_id)
        for hyp in root_cause.hypotheses:
            entry = self.select_entrypoint(hyp, call_path)
            if entry is None:
                result.skipped.append(SkippedHypothesis(hyp.id, "no_reachable_entrypoint"))
                continue
            result.tests.append(self.to_test_case(hyp, entry))
        return result

    def select_entrypoint(self, hypothesis: Claim, call_path: CallPath) -> CallPathEntry | None:
        """가설의 근거(change_id)와 같은 target_change 이면서 app_reachable 이 False 가 아닌 경로 선택.

        여러 개면 노드 수가 가장 적은 경로. 없으면 None (→ skipped).
        """
        raise NotImplementedError

    def to_test_case(self, hypothesis: Claim, entry: CallPathEntry) -> TestCase:
        """가설 + 진입점으로 TestCase 채움 (source="generated", hypothesis_id, change_id, calls, expected_*)."""
        raise NotImplementedError
