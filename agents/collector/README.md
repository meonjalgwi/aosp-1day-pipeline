# Collector Agent

담당: 나연 ([@zv9uvr](https://github.com/zv9uvr))

## 역할

CVE 번호를 입력받아 관련 보안 공지(Android Security Bulletin 등)와 AOSP 패치 커밋을 수집합니다. 영향받는 버전, 컴포넌트, 패치 커밋 링크 등을 구조화된 JSON으로 정리해 Patch Analyst Agent로 전달합니다.

## 입력 / 출력

- 입력: CVE 번호
- 출력: `{ cve, affected_versions, component, patch_commit_url, advisory_url }` 형태의 구조화된 JSON

## 처리해야 할 예외

- 잘못된/깨진 링크
- 비공개(비공개 처리된) 버그 페이지

## 진행 상태

- [ ] 보안 공지 페이지 파싱
- [ ] AOSP Gerrit 패치 커밋 매칭
- [ ] JSON 스키마 확정
- [ ] 잘못된 링크·비공개 버그 예외 처리
