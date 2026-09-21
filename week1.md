# Androrid 전체 아키텍처

## Linux Kernel

Andoroid 플랫폼의 기초는 Linux 커널

ART(Android Runtime)은 스레딩 및 하위 수준의 메모리 관리와 같은 기본 기능에 Linux 커널을 사용함

일반적인 Linux Kernel 기능을 기반으로 다음을 담당

- 프로세스 관리
- 메모리 관리
- 파일 시스템
- 네트워크
- 디바이스 드라이버
- 보안
- 프로세스 간 통신을 위한 Binder 지원

## HAL

하드웨어 추상화 계층. 상위 수준의 Java API 프레임워크에 기기 하드웨어 기능을 노출하는 표준 인터페이스를 제공

Android Framework가 제조사별 하드웨어 차이를 직접 신경 쓰지 않도록 중간에서 인터페이스를 제공

여러 라이브러리 모듈로 구성되며 각 모듈은 특정 유형의 하드웨어 구성요소(카메라나 블루투스 등등)를 위한 인터페이스를 구현함

프레임워크 API가 기기 하드웨어에 엑세스하기 위해 호출을 수행하면 Android 시스템이 해당 하드웨어 구성요소에 대한 라이브러리 모듈을 로드함

## Native

네이티브 C/C++ 라이브러리

ART 및 HAL과 같은 많은 핵심 Android 시스템 구성요소 및 서비스는 C/C++로 작성도니 네이티브 라이브러리가 필요한 네이티브 코드에서 빌드됨

android 플랫폼ㄹ은 자바 프레임워크 API를 제공하여 일부 네이티브 라이브러리의 기능을 앱에 노출함

## ART

Android 앱의 Java/Kotlin 코드를 실행하는 런타임 환경

Android 버전 5.0(API 수준 21) 이상을 실행하는 기기의 경우 각 앱이 자체 프로세스 내에서 자체 ART 인트턴스로 실행됨.

APK 내부에는 보통 `classes.dex`가 존재하고 ART는 이를 실행하면서 JIT/AOT 등의 방식을 사용한다.

ART는 DEX 형식 파일을 실행하여 저용량 메모리 기기에서 여러 가상 머신을 실행하도록 작성됨

DEX 파일은 Android 용으로 설계된 바이트 코드 형식으로 최소 메모리 공간에 맞게 최적화 되어 있음

d8과 같은 빌드 도구는 자바 소스를 Android 플랫폼에서 실행할 수 있는 DEX 바이트 코드로 컴파일함

주요 기능은 다음과 같음

- AOT(Ahead-Of-Time) 및 JIT(Just-In-Time) 컴파일
- 최적화된 가비지 컬렉션(GC)
- 전용 샘플링 프로파일러, 상세 진단 예외 및 오류 보고, watchpoint를 설정하여 특정 필드를 모니터링 할 수 있는 기능을 비롯한 향상된 디버깅 지원 기능

API 21 이하 수준에서는 Dalvik이 Android 런타임이었음. 앱이 APT에서 잘 실행되면 Dalvik에서도 잘 작동되지만, 반대의 경우는 아님

## Framework

앱 개발자에게 Android의 시스템 기능을 API 형태로 제공하는 계층

안드로이드 OS의 전체 기능 세트는 자바 언어로 작성된 API를 통해 액세스 할 수 있음. 이런 API는 핵심 모듈식 시스템 구성요소 및 서비스 재사용을 단순화하여 안드 앱 제작에 필요한 기본 요소를 구성

- view system : 목록, 그리드, 텍스트 상자, 버튼 및 삽입 가능한 웹브라우저를 포함하여 앱의 UI를 빌드하는데 사용할 수 있음
- 리소스 관리자: 문자열, 그래픽, 레이아웃 파일과 같은 코드가 아닌 리소스에 대한 액세스 제공\
- 알림 관리자: 모든 앱이 상태 표시줄에 맞춤 알림을 표시할 수 있도록 지원
- 활동 관리자: 앱의 lifecycle을 관리하고 공통 탐색 백 스택을 제공
- 콘텐츠 제공자: 앱이 연락처 앱과 같은 다른 앱의 데이터에 액세스하거나 자체 데이터를 공유할 수 있도록 함

## App

기본적으로 이메일, SMS 메시지, 캘린더 등 주요 앱 세트가 제공됨. 그렇지만 이 앱은 사용자가 추가로 설치하는 앱과 구별되는 특별한 점은 없음. 즉 기본 SMS 메시지와 카카오톡이 다른게 없다는것. but 시스템 설정 같은건 일부 예외 적용됨


# Andorid 앱 구조

https://velog.io/@gusdkcjs4/Android-APK-%EA%B5%AC%EC%A1%B0-%EC%9D%B4%ED%95%B4%ED%95%98%EA%B8%B0
https://velog.io/@gusdkcjs4/Android-%EC%95%B1-%EC%BB%B4%ED%8F%AC%EB%84%8C%ED%8A%B8

예전에 제가 써놨던 블로그가 있어 대체합니다!


# AOSP 소스 코드 읽기

Android Framework의 주요 소스 코드는 AOSP의 `frameworks/base` 디렉터리에 위치함

`frameworks/base/core/java`에는 앱에서 사용하는 Android Framework API와 Manager 클래스 등이 위치함

- `ActivityManager`
- `NotificationManager`
- `LocationManager`
- `PackageManager` 등

`frameworks/base/services/core/java`에는 실제 시스템 기능을 처리하는 System Service 구현 코드가 주로 위치함

- `ActivityManagerService`
- `WindowManagerService`
- `DevicePolicyManagerService` 등

일반 앱은 높은 권한이 필요한 시스템 기능을 직접 수행하지 않고 Framework API를 통해 System Service에 작업을 요청함

Manager와 System Service는 서로 다른 프로세스에서 동작할 수 있으므로 Binder IPC를 통해 통신함

이 과정에서 AIDL로 정의된 Binder 인터페이스가 사용될 수 있음

일반적인 호출 흐름은 다음과 같음

`App → Manager API → Binder Interface → Binder IPC → System Service → 실제 구현 메서드`

AOSP 코드를 분석할 때는 앱이나 PoC에서 호출하는 Manager API를 시작점으로 하여 Binder 인터페이스와 System Service 구현 메서드까지 호출 흐름을 추적함

System Service 구현에서는 Permission 검사, 호출자 UID 검사, 입력값 검증 등이 수행될 수 있으므로 취약점 분석 시 해당 보안 검사의 존재 여부와 처리 과정을 함께 확인함

Android는 Linux의 사용자 및 프로세스 관리 기능을 기반으로 각 앱과 시스템 구성요소를 격리하며, UID, App Sandbox, Permission, SELinux 등의 여러 보안 계층을 함께 사용함

## PID

PID(Process ID)는 현재 실행 중인 프로세스를 식별하기 위해 운영체제가 부여하는 번호임

Android 앱이 실행되면 해당 앱의 프로세스에도 PID가 할당되며 `system_server`와 같은 시스템 프로세스에도 각각 PID가 존재함

프로세스가 종료된 후 다시 실행되면 새로운 PID가 할당될 수 있으므로 PID는 특정 앱의 권한을 나타내는 값이 아니라 현재 실행 중인 프로세스를 구분하기 위한 값임

Binder를 이용한 IPC 과정에서는 `Binder.getCallingPid()`를 통해 요청을 보낸 프로세스의 PID를 확인할 수 있음

## UID

UID(User ID)는 Linux에서 사용자를 구분하기 위한 식별자이며 Android에서는 앱과 시스템 구성요소의 권한을 구분하는 중요한 보안 기준으로 사용함

Android는 일반적으로 앱을 설치할 때 각 앱에 서로 다른 UID를 할당함

서로 다른 UID를 가진 앱은 Linux 권한 모델에 의해 서로의 파일이나 프로세스에 자유롭게 접근할 수 없음

예를 들어 App A와 App B에 서로 다른 UID가 할당되어 있다면 App A는 기본적으로 App B의 private data 영역에 접근할 수 없음

System Service는 Binder IPC를 통해 요청을 받은 경우 `Binder.getCallingUid()`를 사용하여 요청을 보낸 프로세스의 UID를 확인할 수 있음

따라서 System Service에서는 호출자의 UID를 확인하여 특정 UID에서만 사용할 수 있는 기능을 제한하기도 함

## App Sandbox

App Sandbox는 Android 앱을 서로 격리하기 위한 기본적인 보안 구조임

Android는 각 앱에 서로 다른 Linux UID를 할당하고 Linux의 사용자 기반 접근 제어를 이용하여 앱의 프로세스와 데이터 영역을 다른 앱으로부터 격리함

각 앱은 자신의 private data 영역에는 접근할 수 있지만 다른 UID를 가진 앱의 private data에는 기본적으로 접근할 수 없음

이를 통해 하나의 앱이 악성 동작을 하거나 취약점으로 인해 문제가 발생하더라도 다른 앱의 데이터나 시스템 전체에 직접 영향을 미치는 것을 제한함

일반 앱은 Sandbox 내부에서 실행되기 때문에 높은 권한이 필요한 시스템 작업을 직접 수행할 수 없음

대신 Framework API를 호출하고 Binder IPC를 통해 높은 권한을 가진 System Service에 필요한 작업을 요청하는 구조를 사용함

## Permission

Permission은 앱이 특정 기능이나 데이터에 접근할 수 있는지를 제어하기 위해 사용하는 Android의 접근 제어 방식임

카메라, 위치 정보, 연락처와 같은 사용자 데이터뿐만 아니라 특정 시스템 API나 System Service의 기능에도 Permission이 적용될 수 있음

앱은 필요한 Permission을 `AndroidManifest.xml`에 선언하며 Permission의 종류에 따라 사용자 승인이나 시스템 권한 등이 추가로 필요할 수 있음

System Service에서도 외부에서 들어온 Binder 요청을 처리하기 전에 호출자가 필요한 Permission을 가지고 있는지 검사할 수 있음

AOSP에서는 `checkCallingPermission()`, `enforceCallingPermission()` 등의 형태로 Permission을 검사하는 코드를 확인할 수 있음

필요한 Permission이 없는 호출자가 접근하면 요청을 거부하거나 `SecurityException`을 발생시킬 수 있음

따라서 System Service 취약점을 분석할 때는 취약한 메서드가 존재하는지만 확인하는 것이 아니라 일반 앱이 해당 메서드를 호출하기 위해 어떤 Permission이 필요한지도 확인해야 함

## system UID

Android에는 일반 앱에 할당되는 UID 외에도 시스템 구성요소에서 사용하는 특별한 UID들이 존재함

대표적으로 `root`는 UID 0, `system`은 UID 1000, `shell`은 UID 2000을 사용함

일반적인 서드파티 앱에는 이와 구분되는 앱 UID가 할당되며 일반 앱과 시스템 구성요소 사이에는 권한 차이가 존재함

system UID는 Android의 핵심 시스템 구성요소에서 사용되는 높은 권한의 UID 중 하나임

System Service에서는 `Binder.getCallingUid()`를 이용하여 호출자가 system UID인지 확인하고, system UID에서 들어온 요청에만 특정 기능을 허용하는 경우도 있음

따라서 코드에서 `Process.SYSTEM_UID` 또는 UID 값 `1000`을 확인하는 부분이 존재한다면 호출자의 권한을 기준으로 접근을 제한하는 코드인지 확인할 필요가 있음

## SELinux

SELinux(Security-Enhanced Linux)는 UID와 Android Permission 외에 추가적으로 적용되는 강제적 접근 제어(MAC, Mandatory Access Control) 보안 계층임

Android에서는 각 프로세스를 특정 SELinux Domain에 배치하고 각 시스템 자원에도 보안 Label을 부여함

예를 들어 일반 앱은 `untrusted_app` 계열 Domain에서 실행되고 `system_server`는 `system_server` Domain에서 실행됨

SELinux Policy는 특정 Domain의 프로세스가 다른 프로세스, 파일, Binder Service 등의 자원에 어떤 작업을 수행할 수 있는지를 정의함

따라서 앱이 Android Permission 검사를 통과했거나 특정 UID를 가지고 있다고 하더라도 SELinux Policy에서 해당 접근을 허용하지 않는다면 실제 접근은 차단될 수 있음

SELinux는 앱이나 프로세스가 탈취되었을 때 해당 프로세스가 접근할 수 있는 시스템 자원의 범위를 제한하는 추가적인 보안 경계 역할을 함