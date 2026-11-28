# 유형 커버리지 (1주차 A, #37) - 초안

기준일 2026-11-28. 모든 커밋은 AOSP 미러에서 diff 를 직접 열어 확인했다. 상세는 [cve_inventory.json](cve_inventory.json), 제외 사례는 [excluded_cases.json](excluded_cases.json).

- **수동 분류** = A 가 diff 를 보고 붙인 값 (팀 합의 전 초안)
- **분류기** = B 추출기(PR #35, `aosp1day extract`)를 같은 전·후 소스에 돌린 결과

## Notion 후보 10건 재점검 결과

출처: 김현아의 Notion / 먼잘귀 / 후보 CVE 조사 템플릿

| CVE | 공지 | 대표 커밋 | Notion 기록 커밋과 대조 | 수동 분류 | 분류기 | 상태 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-40105 | 2023-11 | `935eb5ed` | Notion `c31434d6`: 같은 Change-Id, 변경 줄 동일 | GUARD_ADDITION | GUARD_ADDITION | **READY** |
| CVE-2024-31318 | 2024-06 | `b68b257d` | 동일 | API_REPLACEMENT | OTHER | **READY** |
| CVE-2023-40094 | 2023-12 | `1120bc7e` | Notion `7f28e3ea`·`6568e40b`: 같은 Change-Id | GUARD_ADDITION | GUARD_ADDITION | **READY** |
| CVE-2025-0086 | 2025-03 | `c1aa9e66` | 동일 | PRECONDITION_ADDITION | OTHER | **READY** |
| CVE-2023-21113 | 2024-06 | `17dd1124` | Notion `922e52bc`: 같은 Bug, **Change-Id·구현 다름** | OTHER | OTHER | NEEDS_WORK |
| CVE-2023-21244 | 2023-10 | `5a3d0c13` | 동일 (3개 커밋 체인) | OTHER | OTHER | NEEDS_WORK |
| CVE-2022-20448 | 2022-11 | `a367c0a1` | 동일 (CVE 레코드엔 커밋 없음) | GUARD_ADDITION | OTHER | HISTORICAL |
| CVE-2021-0922 | 2021-11 | `be1752c1` | 동일 (CVE 레코드엔 커밋 없음) | OTHER | API_REPLACEMENT | HISTORICAL |
| CVE-2021-0327 | 2021-02 | `69eaa90b` | Notion 기록 커밋 (CVE 레코드엔 커밋 없음) | OTHER | OTHER | HISTORICAL |
| CVE-2023-21029 | Pixel 2023-03 | 없음 | Notion 에도 커밋 미확인 | - | - | EXCLUDED |

Notion 10건: READY 4 · NEEDS_WORK 2 · HISTORICAL 3 · EXCLUDED 1

## 패치 유형별 대표 사례 (Notion + 기준선 + 부족 유형 추가 조사)

| 패치 유형 | READY (수동·분류기 모두 일치) | READY (수동만) | NEEDS_WORK |
| --- | --- | --- | --- |
| `GUARD_ADDITION` | CVE-2023-40105, CVE-2024-0037, CVE-2023-40094 | - | - |
| `PRECONDITION_ADDITION` | CVE-2023-40111 | CVE-2025-0086 | CVE-2024-49740 |
| `API_REPLACEMENT` | CVE-2023-40109 | CVE-2024-31318 | - |
| `OTHER` | - | - | CVE-2023-21113, CVE-2023-21244, CVE-2023-45777 |

**유형 커버리지 = 3 / 3** (수동·분류기가 모두 일치하는 사례만 세어도 3/3)

## 1주차 지표

| 지표 | 값 | 비고 |
| --- | --- | --- |
| 유형 커버리지 | 3/3 | |
| 사용 가능 CVE 비율 | 7/17 (41%) | 조사 17 = 인벤토리 14 + 제외 3. Notion 10건만: 4/10 |
| 제외 사유 분포 | NATIVE_CODE 2 · NO_PUBLIC_COMMIT 1 | HISTORICAL 3건은 제외가 아니라 참고용 |
| 수동 분류 vs 분류기 일치 | 9/14 | 불일치 5건은 아래 팀 결정 항목 |

## 팀 결정이 필요한 것 (수동 분류와 분류기가 다른 5건)

1. **CVE-2025-0086** (수동 PRECONDITION / 분류기 OTHER): `getAuthToken` 안 익명 `Session.onResult` 에 `if (!type.equals(mAccountType)) { onError; return; }` 추가. 분류기가 이 조건문을 잡지 못함 → 익명 클래스 안 조건 추출 누락으로 보임 (B 확인 요청).
2. **CVE-2024-31318** (수동 API_REPLACEMENT / 분류기 OTHER): 호출 교체가 아니라 오버라이드 메서드 교체(`onShellCommand` → `handleShellCommand`). 분류 규칙을 넓힐지, OTHER 로 둘지.
3. **CVE-2023-45777** (수동 OTHER / 분류기 PRECONDITION): `getParcelable(KEY, Intent.class)` → 타입 미지정 호출 + `intent.getClass() != Intent.class` 이면 return. 분류기는 조기 종료 조건만 보고 PRECONDITION 으로 판정.
4. **CVE-2022-20448** (수동 GUARD / 분류기 OTHER, HISTORICAL): `isNotificationForCurrentUser(record)` 조건 추가. 분류기는 이 헬퍼를 `clearCallingIdentity` 경유 BINDER_IDENTITY 로 봐서 Guard 추가가 아니라고 판정.
5. **CVE-2021-0922** (수동 OTHER / 분류기 API_REPLACEMENT, HISTORICAL): `setMode(op, uid, pkg)` → `setUidMode(op, uid)` 교체 + 리팩터링 혼합.

그 밖에:
- **CVE-2023-21244 revert 체인:** 재적용본(`5a3d0c13`)을 대표로 할지.
- **CVE-2023-21113 커밋 두 개:** Notion 의 `922e52bc`(2023-02, 예외 발생)와 CVE 레코드의 `17dd1124`(2024-04, UID/PID 초기화) 중 어느 것을 대체 기준선 커밋으로 쓸지.

## 메모

- **CVE-2023-40094·40105 커밋 불일치는 문제 아님:** Notion 커밋과 CVE 레코드 커밋이 같은 Change-Id 로 묶이는 브랜치별 커밋이다 (design v2.4 L6 `group_by_change_id` 대상).
- **CVE-2023-40109** 의 부모 커밋은 기준선 CVE-2023-40105 패치 커밋(`935eb5ed`)이다.
- **CVE-2024-0037** 은 2024-02 공지 페이지 표에서 보이지 않고 CVE 레코드에서 공지·커밋이 연결된다.
