참고: [이해를 돕기 위한 PPT](https://docs.google.com/presentation/d/11TNJEPbzwmxN78q-d2jed8u96sgCWIq0/edit?usp=sharing&ouid=118212897241149747774&rtpof=true&sd=true)

---
# ▪︎ Android 전체 아키텍처

## ▫︎ 계층 구조

### 1. 리눅스 커널 (Linux Kernel)

* **역할:** 안드로이드 플랫폼의 근간
* **기능:** 보안, 메모리 관리, 프로세스 및 전원 관리, 네트워킹을 담당하며 하드웨어 드라이버 제공
* **특징:** 하드웨어와 운영체제 사이의 핵심 가교

### 2. 하드웨어 추상화 계층 (HAL, Hardware Abstraction Layer)

* **역할:** 하드웨어와 상위 자바 API 프레임워크를 연결하는 표준 인터페이스
* **기능:** 카메라, 블루투스 등 기기 하드웨어 기능을 일관된 방식으로 사용할 수 있도록 추상화하여 노출
* **특징:** 커널 위에서 하드웨어 벤더 구현을 감싸는 계층으로, 프레임워크는 하드웨어에 직접 접근하지 않고 HAL을 거침

### 3. Native C/C++ 라이브러리

* **역할:** 시스템 핵심 기능을 담당하는 C/C++ 기반 라이브러리
* **기능:** SurfaceFlinger(렌더링), OpenGL/Vulkan(그래픽), SQLite(DB), 웹 렌더링 엔진 등 포함
* **특징:** NDK를 통해 개발자가 직접 접근 가능하며, 일부 시스템 서비스는 자바가 아닌 네이티브 환경에서 구동됨

### 4. 안드로이드 런타임 (ART, Android Runtime)

* **역할:** 앱을 실행하는 가상 머신 및 컴파일 환경
* **기능:** DEX 파일 실행, AOT 및 JIT 컴파일러를 통한 성능 최적화, 가비지 컬렉션(GC) 수행
* **특징:** 안드로이드 5.0 이상부터 기본 런타임으로 사용

### 5. Java API Framework

* **역할:** 안드로이드 OS 전체 기능을 자바/코틀린으로 사용할 수 있도록 API 제공
* **기능:** 뷰(View) 시스템, Activity Manager, Notification Manager, Resource Manager 등 포함
* **특징:** 앱 개발자가 가장 많이 접하는 계층

### 6. System App

* **역할:** 홈 화면, 전화, 이메일, 캘린더 등 기기 기본 탑재 핵심 애플리케이션

## ▫︎ 전체 통신 흐름

1. 앱이 **Framework의 Manager API** 호출
2. 내부적으로 **Binder IPC**를 통해 `system_server`의 실제 서비스 구현체로 요청 전달
3. `system_server`가 처리 후 결과를 Binder를 통해 앱으로 반환

> **분석 포인트:** 앱 프로세스와 `system_server`는 물리적으로 격리되어 있으므로 반드시 IPC(Binder)를 거쳐야 하며, 이 경계에서 UID 확인 등의 **권한 체크**가 필수적으로 발생한다.

---

# ▪︎ Android 앱 기본 구조

* **APK:** 앱을 배포하는 패키지 파일
* **Manifest (`AndroidManifest.xml`):** 앱의 설명서. 앱의 컴포넌트, 요구 권한, 타 앱의 접근 가능 여부(`exported`) 등을 선언
* **4대 컴포넌트:**
1. **Activity:** 사용자가 보는 UI 화면 단위
2. **Service:** 화면 없이 백그라운드에서 동작하는 작업 (예: 음악 재생, 다운로드)
3. **BroadcastReceiver:** 시스템이나 타 앱의 방송(이벤트)을 수신 (예: 부팅 완료, 배터리 부족)
4. **ContentProvider:** 앱의 데이터(DB, 파일)를 타 앱과 공유하기 위한 표준화된 인터페이스


> 이 넷은 Manifest에 선언되어야 시스템이 인식하며, `exported="true"` 설정 시 타 앱에서 호출 가능하다. (Intent Injection 취약점과 직결)


* **Intent:** 컴포넌트 간 작업 요청과 데이터를 주고받는 메시지 객체
* **명시적 Intent:** 호출할 컴포넌트를 클래스명으로 정확히 지정
* **암시적 Intent:** 원하는 동작만 선언하고 시스템이 적절한 컴포넌트를 찾도록 위임



> **정리:** PoC 앱 분석 시 'Manifest 노출 컴포넌트 확인 → 해당 컴포넌트가 Intent로 받는 데이터 확인 → 데이터 검증 누락 여부 추적' 순서로 흐름을 파악한다.

---

# ▪︎ AOSP 소스 코드 읽기

보안 취약점 분석의 핵심은 **App 요청이 System Service로 전달되는 과정에서 발생하는 보안 검증의 근본적 누락을 찾는 것**이다.

## ▫︎ 코드 추적 경로 (App → System Service)

1. **Manager API (Client):** `frameworks/base/core/java/.../XxxManager.java` (앱이 호출하는 공개 API, Proxy 역할)
2. **Binder IPC (Interface):** `IXxx.aidl` (통신 규약)
3. **Service 구현체 (Server):** `frameworks/base/services/core/java/.../XxxService.java` (실제 로직이 실행되는 타겟. **취약점 분석의 핵심**)

## ▫︎ 중점 검토 사항

* **권한 검증 누락:** 메서드 도입부에 `enforceCallingPermission()` 또는 `getCallingUid()`를 통한 호출자 권한 확인 로직이 존재하는가?
* **신원 혼동 (Confused Deputy):** `clearCallingIdentity()`로 System 권한으로 상승한 상태에서 외부 입력값을 안전하게 처리하고, `restoreCallingIdentity()`로 정확히 복구하는가?
* **입력값 검증:** 앱이 전달한 `Intent`나 파일 경로를 검증 없이 신뢰하여 실행하는가?

---

# ▪︎ 프로세스 및 보안 구조

안드로이드 보안의 근본 원리는 **앱 간의 철저한 격리**와 **최소 권한 부여**다.

* **앱 샌드박스 & UID/PID:** 각 앱은 고유한 리눅스 UID와 독립된 PID를 할당받아 메모리와 데이터를 격리한다. 이 경계를 넘으려면 합법적인 Binder IPC를 거치거나 취약점을 악용해야 한다.
* **권한 (Permission):** 샌드박스 외부 자원(카메라, 위치 등)에 접근하기 위한 명시적 허가증이다.
* **System UID (UID 1000):** 프레임워크 핵심 서비스가 구동되는 특권 권한. 공격자의 주 목표는 일반 앱 UID에서 이 권한(또는 Root)으로 상승하는 것이다.
* **SELinux:** UID 통제가 우회되더라도, 사전 정의된 정책 레이블이 일치하지 않으면 동작을 강제 차단하는 최후의 보안 방어선.

---

# ▪︎ Binder IPC 및 보안 메커니즘

프로세스 간 메모리 단절이라는 근본 문제를 해결하는 커널 수준의 통신 브릿지다.

## ▫︎ 통신 과정

1. **Parcel:** 전달할 데이터와 요청을 바이트 스트림으로 직렬화
2. **Proxy:** 앱 영역에 존재. 요청을 Parcel로 만들어 Binder Driver로 전달
3. **Binder Driver:** 커널 영역에서 동작. 데이터를 안전하게 배달하고 **호출자의 신원(UID/PID)을 절대적으로 보증**
4. **Stub:** 시스템 서비스 영역에 존재. Parcel을 역직렬화하여 실제 로직 실행 후 결과 반환
5. **AIDL:** Proxy와 Stub 코드를 자동 생성해 주는 인터페이스 정의 도구

## ▫︎ 보안 식별 및 통제 메커니즘

* **호출자 신원 확인:** `Binder.getCallingUid()` / `getCallingPid()`를 통해 커널이 보증한 실제 호출 앱의 신원 확인.
* **권한 검증:** `enforceCallingPermission()`을 통해 해당 UID가 필수 권한을 가졌는지 확인하고, 없으면 예외(SecurityException)를 던져 중단.
* **권한 이양과 복구:**
1. `clearCallingIdentity()`: 잠시 앱 UID를 지우고 System UID 권한으로 상승.
2. 시스템 자원 접근 로직 수행.
3. `restoreCallingIdentity()`: 작업 완료 후 원래 앱 UID로 신원 복구.



> **취약점 분석 포인트:** Stub 실행 지점에서 권한 점검 로직이 누락되었거나, 권한이 System UID로 상승한 상태에서 외부 입력 파라미터를 검증 없이 신뢰할 때 시스템 통제권 상실(Confused Deputy)이 발생한다.

---

# ▪︎ System Service 추적 흐름

앱이 하드웨어나 핵심 자원을 다루기 위해 중앙 관리소(`system_server`)에 요청을 보내는 구조다.

1. 앱이 `getSystemService()`로 `XxxManager` 객체 획득
2. `XxxManager`가 `ServiceManager`를 조회해 타겟 서비스의 Binder Proxy 획득
3. Proxy를 통해 직렬화된 데이터(Parcel)를 Binder Driver로 전송
4. 특권 프로세스인 `system_server`에 요청 진입
5. `system_server` 내 Stub이 역직렬화 후 `XxxService` 구현체 로직 실행 및 권한 검증

> **분석 해결책:** 방어 로직의 허점을 찾을 때는 껍데기인 `XxxManager.java` 분석을 생략하고, 타겟 요청이 도달하는 **`system_server` 내부의 `XxxService.java` 구현체로 직행**하여 외부 입력값과 UID 검증 유무를 파헤쳐야 한다.

---

# ▪︎ Framework 취약점 유형 및 해결 방법

## 1. 권한 및 신원 식별 오류 (Missing Permission Check / Calling Identity)

* **근본 원인:** 시스템 서비스가 호출 앱의 권한을 확인하지 않거나 대상을 잘못 지정함.
* **발생 결과:** 악성 앱의 시스템 설정 변경 등 권한 상승(Privilege Escalation).
* **해결 방법:** API 진입점마다 `enforceCallingPermission()`과 `getCallingUid()`를 삽입하여 호출자를 엄격히 통제한다.

## 2. 특권 대리 실행 및 주입 (Confused Deputy / Intent Injection)

* **근본 원인:** 시스템 서비스가 자신의 특권(System UID) 상태에서, 앱이 전달한 검증되지 않은 의도(Intent, URI 등)를 맹신하고 실행함.
* **발생 결과:** 비공개 시스템 컴포넌트 강제 실행 등 권한 우회 공격.
* **해결 방법:** 외부 Intent 실행 시 타겟을 제한하고, `clearCallingIdentity()` 상태에서도 원래 호출자의 권한으로 접근 가능한지 2차 검증을 수행한다.

## 3. 악의적 입력값 및 경로 조작 (Path Traversal / Input Validation)

* **근본 원인:** 외부에서 조작된 경로 문자열(`../`)이나 규격 외 데이터를 시스템 내부 로직에 그대로 사용함.
* **발생 결과:** 임의 시스템 파일 무단 접근(Data Leak) 및 잘못된 데이터 처리로 인한 서비스 거부(DoS).
* **해결 방법:** `getCanonicalPath()`로 파일 경로를 정규화하여 디렉토리 탈옥을 막고, 모든 외부 입력값의 길이, 타입, 범위를 최우선으로 검증(Sanitization)한다.
