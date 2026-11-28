# sources/ - 기준선 CVE 패치 전·후 원본 소스

1주차 A 작업(#37)의 산출물. B 추출기(`aosp1day extract <CVE>`)의 기본 입력 경로입니다.

## 구조

```
sources/<CVE>/
  before/<저장소 상대 경로>   # 부모 커밋(parent_commit) 시점의 원본 파일 전체
  after/<저장소 상대 경로>    # 패치 커밋(commit) 시점의 원본 파일 전체
  patch.diff                 # git diff <parent> <commit>
  source.json                # 커밋·출처·파일 sha256 메타데이터
```

- 패치가 바꾼 파일만 넣었고, 발췌하지 않은 **원본 전체**라서 줄 번호가 Gitiles 원본과 같습니다.
- 원본은 AOSP GitHub 미러(`aosp-mirror/platform_frameworks_base`)에서 같은 커밋 해시로 받았습니다.

## 기준선

| CVE | 저장소 | 패치 커밋 | 부모 커밋 | 변경 파일 | 공지 |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-40105 | platform/frameworks/base | `935eb5ed6be3` | `08f9c3837384` | ActivityManagerService.java | ASB 2023-11 |
| CVE-2024-0037 | platform/frameworks/base | `55fc00a0788e` | `3e88d987235f` | autofill Helper.java · RemoteInlineSuggestionViewConnector.java · SaveUi.java | ASB 2024-02 |

## 재생성

```bash
git init aosp-fb && cd aosp-fb
git remote add origin https://github.com/aosp-mirror/platform_frameworks_base.git
git fetch --depth=2 --filter=blob:none origin <commit>
git show <parent>:<path> > before/<path>; git show <commit>:<path> > after/<path>
git diff <parent> <commit> > patch.diff
```
