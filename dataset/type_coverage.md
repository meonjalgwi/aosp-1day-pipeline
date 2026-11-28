# 유형 커버리지 (1주차 A, #37) - 초안

기준일 2026-11-28. 모든 행은 AOSP 커밋 diff 를 직접 열어 확인했다. 상세는 [cve_inventory.json](cve_inventory.json), 제외 사례는 [excluded_cases.json](excluded_cases.json).

> Notion 후보 10건 재점검은 아직 반영 전이다 (Notion 목록 확보 후 추가).

## 패치 유형별 대표 사례

| 패치 유형 | 표현 | READY | NEEDS_WORK | 대표 사례 |
| --- | --- | --- | --- | --- |
| `GUARD_ADDITION` | Source-Guard-Sink | 2 | 0 | CVE-2023-40105 (UID_PACKAGE_BINDING), CVE-2024-0037 (URI_USER_BOUNDARY) |
| `PRECONDITION_ADDITION` | Precondition-Target API | 2 | 1 | CVE-2023-40111 (`pi.isActivity()` → `MediaButtonReceiverHolder.create`), CVE-2025-0086 (계정 타입 확인 → `new Account`) / CVE-2024-49740 (다중 저장소) |
| `API_REPLACEMENT` | Unsafe API-Safe API | 1 | 0 | CVE-2023-40109 (`readParcelableArray(ClassLoader)` → `readParcelableArray(ClassLoader, Class)`) |
| `OTHER` | 패치 전·후 차이 조건 | 0 | 1 | CVE-2023-45777 (API 교체 + 클래스 검사 혼합) |

**유형 커버리지 = 3 / 3** (세 유형 모두 READY 대표 사례 1건 이상)

## 1주차 지표 (현재 값)

| 지표 | 값 | 비고 |
| --- | --- | --- |
| 유형 커버리지 | 3/3 | |
| 사용 가능 CVE 비율 | 5/9 (READY ÷ 조사) | 조사 9건 = 인벤토리 7 + 제외 2. Notion 10건 반영 시 갱신 |
| 제외 사유 분포 | NATIVE_CODE 2 | CVE-2023-40091, CVE-2025-48549 |

## 메모

- **CVE-2025-0086 재분류:** B담당 정리(10/30)에서는 AUTH_PERMISSION(권한 검사 누락)으로 봤지만, diff 는 인증자가 돌려준 계정 타입이 요청한 타입과 같은지 확인하는 검사다 → `PRECONDITION_ADDITION`.
- **CVE-2023-40109** 의 부모 커밋은 기준선 CVE-2023-40105 의 패치 커밋(`935eb5ed`)이다. 같은 날 같은 브랜치에 들어간 수정.
- **CVE-2023-45777** 은 `getParcelable(KEY, Intent.class)` 를 타입 미지정 호출 + 정확한 클래스 비교로 바꾼 것이라, 교체와 검사 추가가 섞여 분류기 규칙상 `OTHER`. API_REPLACEMENT 두 번째 사례로 쓸지 팀 판단 필요.
- **CVE-2024-0037** 은 2024-02 공지 페이지 표에서 보이지 않는다. CVE 레코드에서 공지·커밋이 연결돼 있다 (scope-v2.3 출처 메모와 같음).
