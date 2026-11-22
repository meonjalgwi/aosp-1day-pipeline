# 한계와 대응 (v2.3 기준)

> 2026-11-23 · 김나연
> 범위 확장([scope-v2.3.md](scope-v2.3.md))·패치 기반 규칙 생성 파이프라인([novel-patterns.md](novel-patterns.md)) 이후에도 남는 한계와, 각각을 설계 어디에서 어떻게 다루는지 정리한다. 해결할 수 없는 것은 **보고서 "한계" 항목에 수치로 남긴다.**

| # | 한계 | 영향 | 대응 | 반영 위치 | 시점 · 담당 |
| --- | --- | --- | --- | --- | --- |
| L1 | **AOSP 코드 공개 주기.** 2026년부터 소스는 2·4분기에만 공개되고, 개발은 내부 브랜치에서만 진행된다. 권장 브랜치는 `android-latest-release` [1][2] | 스캔 코드가 최대 반년 전 상태 → 후보가 내부에서 이미 고쳐졌을 수 있음. 회고 검증의 시점 해상도가 낮음 | ① 스캔 기준을 **"최신 공개 릴리스 + 이후 보안 공지 패치 적용본"** 으로 정의 (`scan_snapshot`) ② 후보마다 기준 스냅샷 표시 ③ 보고 직전 이후 공지와 대조해 이미 고쳐진 후보는 `superseded` ④ 회고 검증은 공개 릴리스 단위로 시점을 나눔 | design §2.1 `Candidate.scan_snapshot`·`status`, §2.3 `ScanConfig`, §8 M6 `check_later_fixes` | 6주 · 서진 |
| L2 | **기능 플래그로 감싼 패치.** trunk-stable 개발에서 새 동작은 플래그 뒤에 숨긴다 [3]. 실제로 CVE-2024-49722 수정은 `if (Flags.fixAvatarCrossUserLeak())` 아래에 있다 | 패치 후 코드에도 "플래그 꺼짐" 쪽 취약 경로가 남아 차분 오라클이 실패하거나 오탐이 생김 | ① M2 가 `Flags.xxx()`·`android.*.flags` 조건을 감지해 **"플래그 켜짐" 기준의 실효 after 뷰**를 만든다 (else 쪽 경로 제외) ② 오라클·대조군은 실효 after 뷰로 계산 ③ 스캔에서 플래그로 갈리는 후보는 `flag_gated` 배지 | design §2.1 `PatchChange.flag_gated`, §4 M2 `effective_after`, §7 M5 | 5주 · 현아 |
| L3 | **LLM 시간 누수.** LLM 이 이후에 공개된 패치를 학습했을 수 있음 | 회고 검증("앞선 패치로 이후 결함을 미리 찾았나")에서 LLM 이 답을 아는 셈 → 결과 부풀림 | ① 회고 검증 **주 결과는 LLM 끔**(seed 규칙·T1 만, 규칙은 기준 시점에 고정) ② LLM 켠 결과는 별도 표기 ③ 사용 모델의 학습 시점(공개된 cutoff)을 보고서에 기록 | design §11 M11 `retro_eval(llm=False)`, [llm-verification.md](llm-verification.md) 5절 | 7주 · 서진 |
| L4 | **정적 후보 ≠ 확정 취약점.** 동적 재현(M8)은 후속 범위(이번 프로젝트 제외). 실제 도달 가능성(서명 권한, 기기 설정)을 확정 못 함. 라벨은 팀원이 판정 | Precision 의 신뢰도 | ① **라벨 판정 기준표**(아래) ② 상위 후보는 2명이 따로 라벨 → 일치도(Cohen's κ) 보고, 불일치는 토론 후 `hold` ③ 결과 표현은 항상 "후보" ④ 동적 재현은 후속 범위로 두고 이번 프로젝트에서는 하지 않음 | design §12 M10 라벨 화면, §11 M11 `label_agreement` | 7~8주 · 전원 |
| L5 | **미패치 취약점 발견 시 절차 없음** | 공개 발표·저장소로 미공개 결함이 노출될 위험 | **책임 있는 공개 절차**(아래) — 확인 → Android VRP 신고 → 발표는 마스킹본만 | design §17 (신규) | 확인 즉시 · 나연 |
| L6 | **범위 밖으로 남는 영역.** C/C++ 네이티브(예: CVE-2025-48549 의 frameworks/av 수정), 커널, AOSP 에 공개되지 않은 벤더·Pixel 수정, 리소스·설정만 바뀐 패치(예: CVE-2024-49722 의 config.xml), 리팩터링이 섞인 커밋, 브랜치별로 해시가 다른 같은 수정 | 대상 비율·탐지율 해석 | ① `dataset` 이 위 사유별 개수를 집계해 보고서 한계에 표로 기록 ② 같은 수정의 다중 브랜치 커밋은 M1 이 Change-Id 로 묶음 ③ 리팩터링 혼합 커밋은 M2 가 Guard·검사와 무관한 hunk 를 분리 | design §3 M1 `group_by_change_id`, `dataset` 사유 집계 | 5주 · 나연 |
| L7 | **제안서의 베이스라인 비교가 일정에 없음** (코드 유사도 기반 탐색과 비교) | 차별점을 수치로 못 보임 | **Vanir 를 베이스라인으로 그대로 실행** [4] — 같은 기준선·회고 CVE 에서 Vanir 탐지 vs 우리 후보를 비교, "Vanir 가 놓친 정탐 수" 산출. 직접 구현하지 않음 | design §11 M11 `baseline_vanir` | 7주 · 서진 |
| L8 | **일정·인력.** 면담 기록상 이 시기에 시험이 겹치는데, 범위 확장으로 5주 작업이 늘었다 | 5주 마일스톤 지연 | ① 팀 시험 일정을 반영해 5~6주 작업을 다시 배분 ② 줄이는 순서 고정: Track B 일반화 → Kotlin → M9 HTML·영문 → Track C 탭 → T3 탐색형 ③ 매주 금요일 게이트에서 판단 | [scope-v2.3.md](scope-v2.3.md) 4절 K5, 6절 | 이번 주 · 나연 |

---

## 라벨 판정 기준표 (L4)

| 라벨 | 조건 (모두 근거 줄 필요) |
| --- | --- |
| `tp` | ① 일반 앱(서명·특권 권한 없음)이 진입점이나 Source 를 만들 수 있다 ② 요구 Guard·검사가 경로에 없다 ③ Sink 가 다른 앱·사용자의 데이터 또는 상태에 영향을 준다 |
| `fp` | 위 셋 중 하나라도 코드 근거로 반박된다 (예: 서명 권한으로 등록된 서비스, 상위 caller 에서 검사, Sink 가 읽기 전용 로그) |
| `hold` | 근거가 부족하거나 두 라벨러가 불일치 |

- 라벨은 대시보드에서 근거 줄과 함께 저장한다 (`labels.json` `notes`).
- 상위 N 후보는 2명이 독립 라벨 → `M11.label_agreement` 로 κ 계산. κ 가 낮은 패턴은 보고서에 표시.

## 책임 있는 공개 절차 (L5)

1. **확인:** `tp` 후보가 최신 공개 스냅샷 + 이후 보안 공지에서도 고쳐지지 않았는지 확인 (L1 `check_later_fixes`).
2. **격리:** 해당 후보를 `public=False` 로 고정. 저장소·발표 자료·대시보드 공개본(`_public`)에는 위치·코드·호출 경로를 넣지 않는다. 팀 채널에도 위치는 비공개로.
3. **신고:** Android 보안 취약점 보상 프로그램(Google Bug Hunters)으로 재현 정보와 함께 신고. 신고 날짜·ID 만 내부 기록.
4. **발표:** "N 건을 신고했다" 와 마스킹된 패턴 설명만 공개. 공개 시점은 패치 공개 이후로 한다.
5. **멘토 공유:** 신고 전 멘토에게 알리고 학교·교육 과정의 규정이 있으면 따른다.

## 참고

- [1] Android Authority, "Google will now only release Android source code twice a year," 2026-01-06. https://androidauthority.com/aosp-source-code-schedule-3630018/
- [2] Slashdot 요약 (Android Source 공지 인용: `android-latest-release` 권장). https://tech.slashdot.org/story/26/01/06/2154225/
- [3] Gizchina, "Google decides twice a year is enough for Android source code" (trunk-stable, 기능 플래그). https://www.gizchina.com/android-devices/google-decides-twice-a-year-is-enough-for-android-source-code
- [4] Google, "Vanir: Missing Patch Scanner." https://github.com/google/vanir
- CVE-2024-49722 커밋 `e480e189` (플래그 조건 아래 수정), CVE-2025-48549 (frameworks/av 수정 포함) — 11/23 확인
