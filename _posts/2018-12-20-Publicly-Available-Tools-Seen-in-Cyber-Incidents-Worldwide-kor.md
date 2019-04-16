---
title: "[번역] 전세계 사이버 사고에서 발견된 공개 도구들"
layout: post
date: '2018-12-20 00:00:00 -0700'
tag:
- report
headerImage: true
category: blog
author: kerz
---

출처 : https://www.us-cert.gov/ncas/alerts/AA18-284A#Remote%20Access%20Trojan:%20JBiFrost  
번역 및 보완 : Kerz @ null2root

요약
-
* 5개국 (호주, 캐나다, 뉴질랜드, 영국, 미국) 사이버 보안 당국의 공동 연구 활동 보고서 입니다.
* 보건, 금융 정부 및 방위를 포함한 광범위한 핵심 분야의 정보를 손상시키는데 사용되는 5개의 공개 도구들을 강조 하였습니다.
* 해당 도구를 이용하여 침입자는 시스템에서 특정 목표를 달성 할 수 있도록 도와줍니다.
* 네트워크 및 시스템 관리자는 해당 도구들을 제한하고 네트워크에서 악용 탐지하는데 해당 보고서를 참조하여 구현할 수 있습니다.

본문
-
5개국 (호주, 캐나다, 뉴질랜드, 영국, 미국) 사이버 보안 당국의 공동 연구 활동 보고서 입니다.  
이 보고서 내에서는 최근 전세계 사이버 보안 사고에서 침입 목적으로 사용되고 있는 5개의 공개된 도구들을 강조합니다.해당 도구는 하기와 같습니다.
1. Remote Access Trojan (RAT, 원격 관리 도구): JBiFrost
2. Webshell (웹쉘): China Chopper
3. Credential Stealer (사용자 인증정보  탈취 도구): Mimikatz
4. Lateral Movement Framework (동일망 접근 프레임워크): PowerShell Empire
5. C2 Obfuscation and Exfiltration (C&C 난독화 및 프록시 도구): HUC Packet Transmitter
\* ()는 정확한 한글 분류명이 아닐 수 있습니다.

네트워크 및 시스템 관리자는 해당 도구들을 제한하고 네트워크에서 악용을 탐지하는데 해당 보고서를 참조하여 구현할 수 있습니다

이 보고서 내용의 해당 도구들은 부분적인 사용 예제일 뿐이므로, 네트워크 방어를 위해 계획단계에서 해당 도구들만 목록화하여 막는 방법은 올바른 방법이 아닙니다.

네트워크를 공격하기 위한 (해킹)도구들과 기술들 그리고 그 데이터는 다크웹 상의 국가 또는 범죄자들의 영역만으로 간주되어서는 안됩니다. 최근, 다양한 기능을 갖춘 악성 도구는 숙련된 보안 관계자 (펜테스터), 적대적인 국가 및 범죄 조직에서 부터 아마추어 (미숙련된?) 사이버 범죄자에 이르기까지 누구나 사용 할 수 있습니다.

해당 도구들은 보건, 금융 정부 및 방위를 포함한 광범위한 핵심 분야의 정보를 손상시키는데 사용되었습니다. 광범위한 가용성은 네트워크 방어 및 위협 (원문: threat-actor attribution) 에 대한 문제를 제시 합니다.

각 국의 경험에 따르면, 사이버 위협 범죄자는 계속 역량을 개발하지만, 기존의 도구와 기술들도 여전히 사용합니다. 가장 정교한 위협 조직 조차도 공개된 도구들을 사용하여 목적을 달성합니다.

공격자들의 목적이 무엇이든 간에 공격 초기 단계는 피해 시스템에서 흔히 발견되는 취약점을 악용하여 이루어집니다. 공격자들은 일반적으로 미패치 소프트웨어 또는 취약한 시스템을 접근 및 이용합니다. 이 보고서에서 제시된 5개 도구들은 침입자가 피해 시스템에서 목표 달성을 위해 사용하는 역할을 합니다.

보고서 활용 방법
-
도구들은 5개 분류목록 (RAT, 웹쉘, 사용자 인증정보  탈취 도구, 프레임워크, 암호화된 프록시 도구) 로 구분됩니다. 
도구들이 어떤 장소, 시기, 어떻게 배치되며 각 도구들의 위협을 설명합니다. 탐지 및 도구의 사용 제한을 위한 방법도 설명합니다. 
네트워크 방어 활동을 위한 일반적인 조언으로 보고서는 마무리 됩니다. 

기술적 세부 내용
-
**Remote Access Trojan (RAT, 원격 관리 도구): JBiFrost**

2015년 5월 처음 발견된 JBiFrost RAT 는 Adwind RAT 의 변형이며, 2012년의 Frutas RAT 가 원형입니다.

RAT은 프로그램으로, 한번 피해자의 컴퓨터에 설치되면 원격 관리 제어를 허용합니다. 백도어 및 키로거를 설치하고 스크린 샷을 찍고, 데이터를 추출하는 등 여러가지 악성 기능들을 포함하고 있습니다.

악성 RAT들은 탐지가 어려운데, 그것들은 대체적으로 프로그램 실행여부를 보여주지 않거나, 합법적인 프로그램으로 보여지도록 설계 되었기 때문입니다.

포렌식 분석을 막기위해, RAT들은 보안 조치/기능 (작업 관리자) 그리고 네트워크 분석 도구(와이어샤크 등)들을 피해자 시스템에서 비활성화 하도록 알려져 있습니다.

**사용**

JBiFrost RAT는 사이버 범죄자 그리고 미숙련된 위협 행위자들에게 주로 사용되지만, 그 기능들은 정부로부터 지원받는 보안 관계자들이 쉽게 사용할 수도 있습니다.

다른 RAT들은 지능형 지속 공격 (APT: Advanced Persistent Threat) 그룹들에게 널리 사용되고 있습니다. 예를 들면, Adwind RAT 의 경우 항공 및 방위 분야에, Quasar RAT 는 APT 10 그룹에 의해 광범위한 분야에 사용되고 있습니다.

위협 행위자는 우리 국가들 (상기에 언급된 5개국)의 서버들을 악의적인 RAT들을 피해자들에게 전달하거나, 다음 공격을 위해 원격 액세스를 획득하는 목적으로 반복적으로 감염시켰습니다.  또는 은행 자격 증명들, 지적 재산권 또는 개인 식별 정보 (PII) 같은 중요 정보를 탈취 목적으로 감염하였습니다.

**기능**

JBiFrost RAT은 자바 기반, 크로스 플랫폼, 다양한 기능들 가지고 있습니다. 이는 다양한 운영 체제 (윈도우, Linux, MAC OS X, 그리고 안드로이드)에게 위협입니다.

JBiFrost RAT 는 위협 행위자에게 네트워크를 통해 좌우로 이동하거나 (동일 세그먼트 또는 동일 VLAN) 선회하거나 추가적으로 악성 소프트웨어를 설치할 수 있습니다. 이는 주로 이메일 첨부파일 (일반적으로 급여 통지, 견적 요청, 발송 통지, 지불 통지) 또는 호스팅 서버 파일을 링크를 전달하는 방법이 사용됩니다.

과거 감염으로 인해 지적 재산, 은행 자격 증명서, 개인 식별 정보 (PII)가 누출되었습니다. JBiFrost RAT에 감염된 그 컴퓨터들은 봇넷에서 분산형 서비스 거부 공격 (DDoS) 을 수행하는데 사용할 수 있습니다.

**사례**

2018 년 초부터 중요 국가 인프라 소유자와 공급망 운영자에 대한 표적 공격에 JBiFrost RAT가 증가하는 것을 확인했습니다. 우리 나라들 (상기 언급된 5개국)의 위치한 인프라에 대한 RAT의 호스팅 또한 증가했습니다.

2017 년 초 Adwind RAT는 국제 은행간 통신 협회(Worldwide Interbank Financial Telecommunication) 또는 SWIFT 네트워크 서비스에서 온 것처럼 보이도록 설계된 피싱 전자 메일로 배포 되었습니다.

Gh0st RAT의 변형을 비롯하여 다른 많은 공개적으로 사용 가능한 RAT가 전 세계 피해자를 대상으로 사용되는 것으로 확인되었습니다.

**탐지 및 보호**

JBiFrost RAT 감염의 몇 가지 징후는 다음과 같습니다 (다만, 이에 제한되지 않습니다.)

* 안전 모드에서 컴퓨터를  재시작 불가,
* Windows 레지스트리 편집기 또는 작업 관리자를 실행 불가,
* 디스크 활동 및 / 또는 네트워크 트래픽이 크게 증가,
* 알려진 악성 IP (인터넷 프로토콜) 주소에 대한 연결 시도,
* 난독 화되거나 임의의 이름을 가진 새로운 파일 및 디렉토리를 생성.

보호는 시스템 및 설치된 응용 프로그램이 모두 완전히 패치되고 업데이트 됨으로써 보장됩니다. 자동 정의 업데이트와 정기적 인 시스템 검사를 사용하는 최신 바이러스 백신 프로그램을 사용하면 대부분의 최신 변종들이 더 이상 활동 못하도록 보장 할 수 있습니다. 조직 전체에서 바이러스 방지 탐지를 중앙 수집 및 관제 함으로써 RAT 탐지를 효율적으로 조사 할 수 있어야 합니다.

감염을 방지하기 위해 엄격한 응용 프로그램 허용 목록 작성을 권장됩니다.

JBiFrost RAT를 포함한 RAT의 초기 감염 메커니즘은 피싱 전자 메일을 통해 이루어질 수 있습니다. 이러한 피싱 전자 메일이 사용자에게 도달하지 못하게하고, 사용자가 피싱 전자 메일을 식별하고 보고하도록 의식을 개선하고, 악성 전자메일이 컴퓨터를 손상시키지 않도록 보안 제어를 구현함으로써 JBiFrost RAT 감염을 방지 할 수 있습니다. 영국 국립 사이버 보안 센터 (영국 NCSC)에서 [피싱 안내](https://www.ncsc.gov.uk/phishing) 를 게시했습니다.

**Webshell (웹쉘): China Chopper**

"China Chopper"는 공개적으로 사용 가능하고 잘 문서화 된 웹쉘로서 2012 년부터 널리 사용되었습니다.

Webshell은 초기 침해 후 대상 호스트에 업로드되고 위협 행위자에게 원격 관리 기능을 부여하는 악의적 인 스크립트입니다.

이 접근 환경이 구축되면, webshell을 사용하여 네트워크 내의 추가 호스트로 연결 할 수 있습니다.

**사용**

China Chopper는 위험 행위자가 원격으로 손상된 웹 서버에 접근하여 손상된 장치에서 가상 터미널에 대한 접근과 함께 파일 및 디렉토리 관리를 제공하는 등 광범위하게 사용합니다.

China Chopper는 크기가 4KB에 불과하며 수정 가능한 페이로드가 있기 때문에 네트워크 보안 관리자에게는 탐지 및 조치가 어렵습니다. 

**기능**

China Chopper는 공격자가 실행하는 China Chopper 클라이언트 측과 피해자 웹 서버에 설치되고 공격자가 제어하는 ​​China Chopper 서버라는 두 가지 주요 구성 요소를 가지고 있습니다.

(Webshell은 단순하게 서버 언어로 1줄로 구성되었고, 이를 접속하는 클라이언트가 바이너리인 2가지 구성요소를 가지고 있습니다.)

webshell 클라이언트는 터미널 명령을 실행하고 대상 서버에서 파일을 관리 할 수 ​​있습니다. 하기 MD5 해시가 공개되었고 사용 가능합니다 (원본은 hxxp://www.maicaidao.com에 게시 됨).

(MD5 해시는 확인해서 탐지 및 차단에 이용 또는 분석 시 변조된 파일이 존재 할 수 있으므로 사용 시 주의하라는 의미로 넣은 것으로 파악되며, 현재 해당 사이트는 접근 안됨)

웹 클라이언트의 MD5 해시는 아래 표 1에 나와 있습니다. 

**Table 1: China Chopper webshell client MD5 hash**

|Webshell Client|MD5 Hash|
|---|---|
|caidao.exe|5001ef50c7e869253a7c152a638eab8a|

webshell 서버는 일반 텍스트 형식으로 업로드되며 공격자가 쉽게 변경할 수 있습니다. 따라서 적대적인 활동을 식별 할 수있는 특정 해시를 정의하는 것이 더 어려워집니다. 2018 년 여름에 CVE-2017-3066에 취약한 공개 웹 서버를 대상으로 위협 활동이 확인되었습니다. 이 활동은 원격 코드 실행을 가능하게하는 웹 응용 프로그램 개발 플랫폼 인 Adobe ColdFusion의 취약점과 관련이 있었습니다.

China Chopper는 서버가 손상되면 제공되는 두 번째 단계 페이로드로 사용되어 위협 행위자가 대상 호스트에 원격 접근 할 수 있습니다. 피해 컴퓨터의 취약점을 성공적으로 악용 한 후 텍스트 기반 China 쵸퍼는 대상 웹 서버에 배치됩니다. 일단 업로드되면 클라이언트 응용 프로그램을 사용하여 언제든지 위협 요소가 webshell 서버에 액세스 할 수 있습니다. 성공적으로 연결되면 위협 행위자는 웹 서버의 파일과 데이터를 조작합니다.

China Chopper의 기능은 파일 검색 도구 `wget` 을 사용하여 인터넷에서 파일을 대상으로 다운로드하여 피해자와주고받는 파일 업로드 및 다운로드를 포함합니다. 기존 파일의 편집, 삭제, 복사, 이름 바꾸기, 타임 스탬프 변경 등이 포함됩니다.

**탐지 및 보호**

웹 쉘에 대한 가장 강력한 방어책은 웹 서버가 처음부터 손상되는 것을 피하는 것입니다. 공개 웹 서버에서 실행되는 모든 소프트웨어가 적용된 보안 패치로 최신 버전인지 확인하십시오. 일반적인 웹 취약점에 대한 사용자 지정 응용 프로그램을 감사를 실시하십시오. [[6]](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)

China Chopper의 한 가지 속성은 모든 동작이 HTTP POST를 생성한다는 것입니다. 네트워크 보안 관계자는 해당 메소드의 트래픽이 높은 것을 조사하는 경우 쉽게 발경 할 수 있습니다.

China Chopper webshell 서버 업로드는 일반 텍스트이고, 클라이언트가 발행 한 명령은 Base64로 인코딩되어 있습니다 인코딩은 쉽게 해독 할 수 있습니다.

웹 서버에서 TLS (Transport Layer Security)를 채택하면서 웹 서버 트래픽이 암호화되어 네트워크 기반 도구를 사용하여 China Chopper 활동을 탐지하는 것이 더 어려워졌습니다.

China Chopper를 탐지하고 조치하는 가장 효과적인 방법은 호스트 자체, 특히 인터넷 기반 웹 서버에 있습니다. Linux 및 Windows 기반 운영 체제에서 명령 줄을 사용하여 웹 셸의 존재 여부를 검색하는 간단한 방법이 있습니다. [[7]](http://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html)

Webshell을 보다 광범위하게 탐지하기 위해 네트워크 보안 관계자는 웹 서버에서 의심스러운 프로세스 실행 (예 : 하이퍼 텍스트 전처리 기 [PHP] 바이너리 생성 프로세스)과 웹 서버의 비정상 패턴 외부발 (내부->외부) 네트워크 연결을 발견하는 데 주력해야합니다. 일반적으로 웹 서버는 내부 네트워크에 예측 가능한 연결을 설정합니다. 이러한 패턴의 변화는 Webshell 의 존재를 나타낼 수 있습니다. 네트워크 권한을 관리하여 웹 서버 프로세스가 PHP를 실행할 수있는 디렉토리에 쓰거나 기존 파일을 수정하지 못하게 할 수 있습니다.

트래픽 분석과 같이 웹 접근 로그를 모니터링 소스로 사용하는 것이 좋습니다. 예상치 못한 페이지 또는 트래픽 패턴의 변화가 초기 지표 일 수 있습니다.

**Credential Stealer (사용자 인증정보  탈취 도구): Mimikatz**

2007 년에 개발 된 Mimikatz는 공격자가 주로 대상 Windows 컴퓨터에 로그인 한 다른 사용자의 자격 증명을 수집하는 데 사용됩니다. LSASS (Local Security Authority Subsystem Service)라는 Windows 프로세스 내 메모리에있는 자격 증명에 접근하여 수행합니다.

이러한 자격 증명 (인증 정보)은 일반 텍스트 또는 해시 형식으로 이를 재사용하여 네트워크의 다른 컴퓨터에게 접근 권한을 부여 할 수 있습니다.

초기에는 해킹 도구로 의도되지 않았지만, 최근 몇 년동안 위협 행위자들은 Mimikatz 는 악의적인 목적으로 사용했습니다. 

전 세계적으로 이 도구 사용은 전 세계의 조직들로 하여금 그들의 네트워크 방어를 재평가하도록 자극했습니다.

Mimikatz는 일반적으로 호스트에 대한 접근 권한이 확보되면 위협 행위자가 내부 네트워크로 이동하려는 경우 사용합니다. 이를 사용하면 잘못 구성된 네트워크 보안을 크게 손상 시킬 수 있습니다.

**사용**

Mimikatz 소스 코드는 공개되어 있습니다. 즉, 누구나 새로운 도구의 자체 버전을 컴파일하고 잠재적으로 새로운 Mimikatz 사용자 지정 플러그 인 및 추가 기능을 개발할 수 있습니다.

우리 사이버 당국은 조직 범죄 및 주정부 후원 단체를 포함한 위협 행위자들 사이에서 Mimikatz 광범위하게 사용되는 것을 목격했습니다.

일단 위협 행위자가 호스트에 대한 로컬 관리자 권한을 얻으면 Mimikatz는 다른 사용자의 해시 및 일반 텍스트 자격 증명(인증 정보)을 얻는 기능을 제공하여 위협 행위자가 도메인 내의 권한을 상승시키고 더 많은 탈취 및 동일 네트워크로 이동을 수행하는 작업을 할 수있게합니다.

이러한 이유로 Mimikatz는 PowerShell Empire 및 Metasploit과 같은 다른 침투 테스트 및 개발 스위트(패키지)에 번들이되었습니다.

**기능**

Mimikatz는 메모리에서 일반 텍스트 자격 증명과 해시를 검색 할 수있는 능력으로 가장 잘 알려져 있지만 전체적인 기능은 광범위합니다.

이 도구는 Windows XP (2003)에서 Windows 8.1 (2012r2)까지 LAN (Local Area Network Manager) 및 NT LAN Manager 해시, 인증서 및 장기간용 (long-term) 키를 추출 할 수 있습니다. 또한 해시 패스 또는 티켓 패스 (pass-the-ticket) 작업을 수행하고 Kerberos의 "황금 티켓"을 구축 할 수 있습니다. 

(추가내용: Kerberos 는 티켓을 이용한 인증 플랫폼을 사용, 임의의 서버에 인증할 때 나만의 티켓을 만들고 처리할 수 있는 작업을 골든 티켓으로 가능하다. 상세내용은 - [Link](https://digital-forensics.sans.org/blog/2014/11/24/kerberos-in-the-crosshairs-golden-tickets-silver-tickets-mitm-more))

Mimikatz의 많은 기능은 PowerShell과 같은 스크립트를 사용하여 자동화 할 수 있으므로 위협 행위자가 손상된 네트워크를 신속하게 악용하여 사용할 수 있습니다. 또한 자유롭게 사용할 수있는 "Invoke-Mimikatz" PowerShell 스크립트를 통해 메모리에서 작업 할 때 Mimikatz 활동을 격리하고 식별하기가 매우 어렵습니다.

**사례**

Mimikatz는 수년간 광범위한 위협 행위자에 의해 여러 사건에 걸쳐 사용되어 왔습니다. 2011 년에는 알려지지 않은 위협 행위자가 네덜란드 인증 기관인 DigiNotar로부터 관리자 자격 증명 (인증저보)을 얻기 위해 사용되었습니다. DigiNotar의 신뢰가 급속히 상실됨에 따라 회사는이 감염으로 한 달 이내에 파산 신청을 하게 됩니다.

최근에는 Mimikatz가 2017 년 NotPetya 및 BadRabbit ransomware 공격에서 수천 대의 컴퓨터에 대한 관리자 자격 증명 (인증 정보)을 추출하는 데 사용되었습니다. 이러한 자격 증명 (인증 정보)은 동인 네트워크 내 이동을 용이하게하기 위해 사용되었으며 네트워크에 전파되는 ransomware에 사용되어 추출된 자격 증명이 유효한 수많은 시스템의 하드 드라이브를 암호화 시켰습니다.

추가적으로, Microsoft 연구 팀은 몇몇의 고도화(high-profile) 기술 및 금융 기관을 대상으로한  정교한 사이버 공격 중 Mimikatz 사용을 확인하였습니다.다른 여러 도구와 취약점과 함께 Mimikatz는 시스템 해시를 덤프하고 재사용하는 데 사용되었습니다.

**탐지 및 조치**

Windows를 업데이트하면 Mimikatz 도구에서 위협 행위자가 사용할 수있는 정보를 감소 시킬 수 있습니다. Microsoft는 새로운 Windows 버전마다 제공되는 보호 기능을 향상시키기 위해 노력하고 있습니다.

Mimikatz 자격 증명 검색을 방지하려면 네트워크 보안 관계자가 LSASS 메모리에서 일반 텍스트 암호 저장을 비활성화해야합니다. 이는 Windows 8.1 / Server 2012 R2 이상에서는 기본 동작이지만 관련 보안 패치가 설치된 구형 시스템에서는 별도 설정 할 수 있습니다. [[8]](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a) Windows 10 및 Windows Server 2016 시스템은 자격 증명 가드와 같은 최신 보안 기능을 사용하여 보호 할 수 있습니다.

Credential Guard는 다음과 같은 경우 기본적으로 활성화됩니다.

* 이 하드웨어는 Windows Server 2016 및 Windows Server Semi-Annual Branch에 대한 Microsoft의 Windows 하드웨어 호환성 프로그램 사양 및 정책을 충족합니다.
* 서버가 도메인 컨트롤러로 작동하지 않습니다.

실제 및 가상화 서버가 [Windows 10 및 Windows Server의 각 릴리스에 대한 Microsoft의 최소 요구 사항을](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements) 충족하는지 확인해야 합니다.

계정 전반(특히 관리자 계정)의 암호 재사용은 해시 전달 (pass-the-hash) 공격을 훨씬 간단하게 만듭니다. 조직 내에서 네트워크의 일반 수준 계정에서도 암호 재사용을 방해하는 사용자 정책을 설정해야합니다. 무료로 제공되는 Microsoft의 Local Administrator Password Solution을 사용하면 로컬 관리자 암호를 쉽게 관리 할 수 있으므로 수동으로 암호를 설정하고 저장할 필요가 없습니다.

네트워크 관리자는 비정상적이거나 승인되지 않은 계정 생성 또는 인증을 위한 Kerberos 티켓 사용 또는 네트워크의 지속적인 사용 및 동일망 접근을 방지하기 위해 모니터링하고 대응해야합니다. Windows의 경우 Microsoft Advanced Threat Analytics 및 Azure Advanced Threat Protection과 같은 도구를 사용하면 도움이 됩니다.

네트워크 관리자는 시스템에 패치를 적용하고 최신 상태로 유지해야합니다. Mimikatz의 여러가지 기능이 최신 시스템 버전 및 업데이트로 완화되거나 상당히 제한됩니다. 그러나 Mimikatz가 지속적으로 개선되고 새로운 제 3 자 모듈이 종종 개발되기 때문에 업데이트가 완벽하지 않습니다.

가장 최신의 바이러스 백신 도구는 사용자 지정되지 않은 Mimikatz 사용을 검색하고 격리하므로 이러한 인스턴스를 검색하는 데 사용해야합니다. 그러나 위협 행위자는 때때로 Mimikatz를 메모리에서 실행하거나 도구의 원래 코드를 약간의 수정으로 바이러스 백신 시스템을 우회 할 수 있습니다. Mimikatz가 발견되면 어디에서나 엄격한 조사를 수행해야합니다. 위협적인 행위자가 네트워크에서 적극적으로 활동하고 있음을 말합니다.

Mimikatz의 기능 중 일부는 관리자 계정의 악용에 의존합니다. 따라서 관리자 계정은 필요한 경우에만 제공되어야합니다. 관리자 권한이 필요한 경우, 권한 접근에 대한 관리 방침을 적용해야 합니다.

Mimikatz는 손상된 시스템에 로그인 한 사용자의 계정 만 캡처 할 수 있으므로 권한이 부여 된 사용자 (예 : 도메인 관리자)는 권한있는 자격 증명으로 컴퓨터에 로그인하지 않아야합니다. Active Directory 보안에 대한 자세한 내용은 Microsoft에서 제공합니다. [[9]](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

(mimikatz는 해쉬 및 인증 정보를 컴퓨터내 메모리에서 추출하므로, 한번이라도 로그인된 사용자만 추출 가능합니다.)

네트워크 보안 관계자는 스크립트, 특히 PowerShell의 사용을 감사하고 로그를 검사하여 예외를 식별해야합니다. 이렇게하면 Mimikatz 또는 해쉬 전달(pass-the-hash)의 남용을 식별하고 탐지 소프트웨어를 우회하려는 시도에 대한 완화를 제공하는 데 도움이 됩니다.

**Lateral Movement Framework (동일망 접근 프레임워크): PowerShell Empire**

PowerShell Empire는 exploit 성공 후 (post-exploitation, 권한 획득 이후) 또는 내부 네트워크 접근 도구의 예입니다. 공격자 (침투 테스터)가 초기 접근권한을 얻은 후 네트워크를 돌아 다니도록 설계되었습니다. 이러한 도구의 다른 예로는 Cobalt Strike 및 Metasploit이 있습니다. 또한 PowerShell Empire를 사용하여 네트워크에 대한 소셜 엔지니어링 접근 획득을 위한 악성 문서 및 실행 파일을 생성 할 수 있습니다.

PowerShell Empire 프레임 워크는 2015 년에 합법적 인 침투 테스트 도구로 설계되었습니다. PowerShell Empire는 위협 행위자가 시스템에 접근하면 지속적인 악용을위한 프레임 워크 역할을 합니다.

이 도구는 권한 상승, 자격 증명 (인증 정보) 수집, 정보 추출 및 네트워크를 통한 내부망 접근 기능을 위협 행위자에게 제공합니다. 이러한 기능으로 강력한 악용 도구가됩니다. 일반적으로 합법적인 응용 프로그램 (PowerShell)을 기반으로하며 거의 모든 기능을 메모리에서 수행 할 수 있으므로 PowerShell Empire는 기존의 바이러스 백신 도구를 사용하여 네트워크에서 검색하기가 어려울 수 있습니다

**사용**

PowerShell Empire는 반국가적인 위협자와 조직 범죄자들 사이에서 점점 인기를 얻고 있습니다. 최근 몇 년 동안 우리는 다양한 분야의 사이버 사고에서 전 세계적으로 사용되는 것을 보아 왔습니다.

초기 탈취 방법은 손상 에 따라 다르며 위협 행위자는 각 시나리오 및 대상에 대해 PowerShell Empire를 고유하게 구성 할 수 있습니다. PowerShell Empire 사용자 커뮤니티의 광범위한 기술 및 의도와 함께 사용하면 발견이 쉽지 않습니다. 그럼에도 불구하고,이 도구에 대한 더 큰 이해와 인식은 위협 행위자의 사용을 막는데 큰 도움을 주는 단계입니다. 

**기능**

PowerShell Empire는 위협 행위자가 피해자의 컴퓨터에서 일련의 작업을 수행 할 수있게하고 powershell.exe가 시스템에 존재하지 않고도 PowerShell 스크립트를 실행할 수있는 기능을 구현합니다. 통신은 암호화되고 아키텍처는 유연합니다.

PowerShell Empire는 "모듈"을 사용하여보다 구체적인 악의적 인 작업을 수행합니다. 이 모듈은 위협 요소에 사용자의 시스템에서 목표 달성 을 위한 옵션을 제공합니다. 이러한 목표에는 권한 확대(상승), 자격 증명 수집, 호스트 열거 (목록화), 키 로깅 및 네트워크를 통해 내부 접근 공격 기능이 포함됩니다.

PowerShell Empire의 사용 용이성, 유연한 구성 및 탐지를 회피하는 기능은 다양한 능력을 가진 위협 행위자에게 널리 사용됩니다. 

**사례**

2018 년 2 월의 한 사건에서 영국의 에너지 분야 회사는 알려지지 않은 위협 행위자에 의해 침해당했습니다. 해당 손상은 도구의 기본 프로필 설정을 사용하여 PowerShell Empire 신호(beaconing) 활동을 통해 탐지되었습니다. 피해자의 관리자 계정 중 하나에 대한 취약한 자격 증명은 위협 행위자에게 네트워크에 대한 초기 접근 권한을 제공 한 것으로 보여집니다.

2018 년 초, 알려지지 않은 위협 행위자가 동계 올림픽 테마의 조작된 소셜엔지니어링 이메일과 악성 첨부 파일을 여러 한국 기업을 대상으로한 피싱 공격에 사용했습니다. 이 공격에는 PowerShell 스크립트를 이미지로 인코딩 할 수있는 지능화된 도구 인 `Invoke-PSImage` 를 사용하여 한층 세련된 레이어가 추가되었습니다.

2017 년 12 월 APT19는 다국적 법률 사무소를 대상으로 피싱 공격을 실시했습니다. APT19는 PowerShell Empire에서 생성 한 Microsoft Word 문서에 포함 된 난독화 된 PowerShell 매크로를 사용했습니다.

우리 사이버 보안 당국 (5개국) 은 학계를 대상으로 사용되는 PowerShell Empire에 대해서도 인식하고 있습니다. 보고 된 한 사례에서 위협 행위자는 PowerShell Empire를 사용하여 Windows Management Instrumentation 이벤트 소비자 (event consumer, MS 문서에도 이렇게 표현하네요) 를 사용하여 지속성을 확보하려고 시도했습니다. 그러나 이 경우 PowerShell Empire 에이전트는 로컬 보안 어플라이언스(솔루션) 에 의해 HTTP 연결이 차단되어 네트워크 연결을 설정하는 데 실패했습니다.

**탐지 및 차단**

악의적인 PowerShell 활동 탐지는 어려울 수 있는데, 그 이유는 호스트내 합법적인 PowerShell 활동 확산과 기업 환경 유지 (운영)을 위한 PowerShell 사용이 증가했기 때문입니다.

잠재적인 악의적 스크립트 탐지를 위해, PowerShell 활동은 전반적으로 기록되어야 합니다. 이는 스크립트 차단 로깅과 Powershell 증명서(?)도 포함되어야 합니다.

이전 버전의 PowerShell은 최신 버전의 PowerShell에 추가된 로깅 및 컨트롤을 우회하는데 사용될 수 있으므로, 환경에서 제거해야 합니다. 이 페이지는 PowerShell 보안 사례에 대한 요약을제공합니다. [[10]](https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/)

최신 Windows 버전에서 코드 무결성 기능을 사용하면 악의적인 PowerShell의 기능을 제한하여 침입 성공 시 악의적인 Powershell을 예방하거나 공격을 방해할 수 있습니다.

스크립트 코드 서명, 응용 프로그램 허용 (Whitelisting) 및 제한된 언어 모드를 조합하면 침입 성공 시 PowerShell 영향을 방지하거나 제한 할 수 있습니다. 이러한 컨트롤은 합법적인 (정상적인) PowerShell 스크립트에도 영향을 미치므로 배포전 철저하게 테스트를 거치는 것이 좋습니다.

조직에서 Powershell 사용량을 프로파일링 (측정)하면, 그들은 대부분 소수의 기술 직원으로부터 사용된 합법적으로 사용한 경우가 맛흡니다. 이러한 합법적인 활동의 범위를 설정하면, 다른 네트워크에서 의심되거나 예기치 않은 PowerShell 사용을 쉽게 모니터링하고 조사 할 수 있습니다.

**C2 Obfuscation and Exfiltration (C&C 암호화 및 프록시 도구): HUC Packet Transmitter**

공격자는 대부분은 목표물을 손상시킬 때 자신의 위치를 숨기고 싶어 합니다. 이렇게 하기 위해선, 그들은 그들의 위치를 난독화 하기 위해 일반적인 개인 정보 도구들 (예 Tor) 또는 특정 도구들을 사용할 것 입니다.

HUC Packet Transmitter (HTran, HUC 패킷 전송기)은 로컬 호스트에서 원격 호스트로 전송 제어 프로토콜 (TCP) 연결을 가로 채거나, 리다이렉션 하는데 사용되는 프록시 도구입니다. 이를 통해 피해 네트워크와 공격자의 통신을 난독화할 수 있습니다. 이 도구는 2009년 이후 인터넷에서 무료로 사용 가능합니다.

HTran은 피해자와 위협 행위자에 의해 통제 된 홉 (hop) point 사이의 TCP 연결을 편하게 합니다. 악의적인 위협 행위자는 이 기술을 사용하여 HTran을 실행하는 손상된 여러 호스트를 통해 패킷을 리다이렉트하여 네트워크의 호스트에 더 쉽게 (greater) 접근할 수 있습니다.

HTran은 피해자와 위협 행위자에 의해 통제 된 홉 점 사이의 TCP 연결을 용이하게합니다. 악의적 인 위협 행위자는이 기술을 사용하여 HTran을 실행하는 손상된 여러 호스트를 통해 패킷을 리다이렉하여 네트워크의 호스트에 더 잘 액세스 할 수 있습니다.

**사례**

HTran의 사용은 정부와 산업 분야의 손상된 (해킹된) 대상들에서 정기적으로 관찰되고 있습니다.

HTran 및 기타 포록시 도구를 사용하여 광범위한 위협 요소가 관찰되고 있습니다.

* 네트워크 상의 침임 및 탐지 시스템 회피,
* 일반적인 트래픽과 결합하거나 도메인 신뢰 관계들을 활용하여 보안 제어를 우회,
* C&C 인프라 또는 통신을 난독화 또는 은닉, 그리고
* 탐지를 피하고 인프라에 탄력적인 연결을 제공하기 위한 P2P (Peer-to-Peer) 또는 메시형 (그물형) C&C 인프라를 생성

**기능**

HTran 은 몇가지 모드로 실행 될수 있으며, 각 모드는 두 개의 TCP 소켓을 연결(bridging)하여 네트워크를 통해 트래픽을 전달합니다. TCP 소켓이 로컬 또는 원격으로 부터 초기설정되어 (initialted) 실행 됩니다. 세가지 모드들은 다음과 같습니다.

* **Server (listen)** – TCP 소켓들 둘 다 원격으로 실행
* **Client (slave)** – TCP 소켓들 모두 로컬에서 실행
* **Proxy (tran)** – 하나의 TCP 소켓은 원격으로 실행, 다른 하나는 첫 번째 연결에서 트래픽을 수신하면 로컬로 실행

/* 리버스 커넥션을 설명하는 내용인데 번역해서 보니 좀 난잡하네요 */

HTran은 실행중인 프로세스에 자신을 삽입 할 수 있으며 루트킷을 설치하여 호스트 운영 체제에서 네트워크 연결을 숨길 수 있습니다. 이 기능을 사용하면 HTran이 대상 네트워크에 대한 지속적인 접근을 유지할 수 있도록 Windows 레지스트리 항목이 만들어집니다.

**예제**

우리 사이버 보안 당국의 최신 조사에 따르면 대상 환경에 대한 HTran 을 사용하여 유지 관리하고 난독화하기 위한 원격 접속에 대한 탐지 하였습니다.

한 건의 사건에서, 위협 행위자는 오래되고 취약한 웹 어플리케이션을 실행하는 외부에서 접근이 가능한 웹 서버를 손상 시켰습니다. 이 접근을 통해 Htran 을 포함된 다른 도구를 배포하는데 사용된 webshell를 업로드하여 활성화 하였습니다.

HTran을 ProgramData 폴더에 설치하고 다른 배포 도구를 사용하여 RDP (원격 데스크톱 프로토콜) 통신을 허용하도록 재구성하였습니다. (RDP 활성화 했다는 것)

위협 행위자는 HTran을 통해 로컬 인터페이스에서 RDP 트래픽을 포트 80로 전달 받도록 명령을 내려, 인터넷에서 해당 서버로 포트 80을 통해 RDP 연결을 시작하였습니다. /* 의역 */

이 경우 HTTP는 웹 서버에서 인터넷으로 시작된 것으로 예상되는 다른 트래픽과 혼합되도록 선택되었습니다. 사용 된 다른 well-known 포트는 다음과 같습니다.

* Port 53 – Domain Name System
* Port 443 - HTTP over TLS/Secure Sockets Layer
* Port 3306 - MySQL
* 이런 방식으로 HTran을 사용함으로써 위협 행위자는 탐지되지 않고 몇 달 동안 RDP를 사용할 수 있습니다.

**탐지 및 방지**

공격자는 Htran을 설치하고 실행하기 위해 컴퓨터에 접근해야하므로 네트워크 보안 관계자는 보안 패치를 적용하고 올바른 접근 제어를 사용하여 공격자가 악성 어플리케이션을 설치 못하게 해야 합니다.

[네트워크 모니터링](https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes) 및 방화벽은 HTran과 같은 도구로부터 무단 연결을 방지하고 탐지하는 데 도움이 될 수 있습니다.

분석 된 샘플 중 일부에서는, 프록시 모드가 사용될 때 HTran의 루트킷 구성 요소가 연결 세부 정보만 숨깁니다. 클라이언트 모드가 사용될 때, 보안 관계자들은 TCP 연결에 대한 세부 정보를 볼 수 있습니다.

HTran 또한 네트워크 보안 관계자에게 유용한 디버깅 조건 (condition, 요소?)이 포함되어 있습니다. 대상을 사용할 수 없게되면 HTran은 다음 형식을 사용하여 오류 메시지를 생성합니다.

`sprint(buffer, “[SERVER]connection to %s:%d error\r\n”, host, port2);`

이 오류 메시지는 연결 중인 클라이언트에 전달됩니다. 네트워크 보안 관계자는 이 오류 메시지를 모니터링하여 해당 환경에서 활성화 된 HTran 인스턴스를 잠재적으로 검색 할 수 있습니다.


완화
-

조직의 전반적인 사이버 보안을 향상시키고 이 보고서에서 강조된 도구의 유형에 대해 보호 할 수 있는 몇가지 방법이 있습니다. 네트워크 보안 관계자는 아래의 링크를 사용하여 추가 정보를 찾아보는 것이 좋습니다.
* 악성 프로그램으로 부터 당신의 기관을 보호 (원문: Protect your organization from malware).  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST13-003.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/protecting-your-organisation-malware.  
* Board toolkit: five question for your board’s agenda.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/board-toolkit-five-questions-your-boards-agenda.  
* Use a strong password policy and multifactor authentication (also known as two-factor authentication or two-step authentication) to reduce the impact of password compromises.  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST05-012.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services and https://www.ncsc.gov.uk/guidance/setting-two-factor-authentication-2fa.  
* Protect your devices and networks by keeping them up to date. Use the latest supported versions, apply security patches promptly, use antivirus and scan regularly to guard against known malware threats.  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST04-006.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/mitigating-malware.  
* Prevent and detect lateral movement in your organization’s networks.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/preventing-lateral-movement.  
* Implement architectural controls for network segregation.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/10-steps-network-security.  
* Protect the management interfaces of your critical operational systems. In particular, use browse-down architecture to prevent attackers easily gaining privileged access to your most vital assets.  
    See UK NCSC blog post: https://www.ncsc.gov.uk/blog-post/protect-your-management-interfaces.  
* Set up a security monitoring capability so you are collecting the data that will be needed to analyze network intrusions.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes.  
* Review and refresh your incident management processes.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/10-steps-incident-management.  
* Update your systems and software. Ensure your operating system and productivity applications are up to date. Users with Microsoft Office 365 licensing can use “click to run” to keep their office applications seamlessly updated.  
* Use modern systems and software. These have better security built-in. If you cannot move off out-of-date platforms and applications straight away, there are short-term steps you can take to improve your position.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/obsolete-platforms-security-guidance.  
* Manage bulk personal datasets properly.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/protecting-bulk-personal-data-introduction.   
* Restrict intruders' ability to move freely around your systems and networks. Pay particular attention to potentially vulnerable entry points (e.g., third-party systems with onward access to your core network). During an incident, disable remote access from third-party systems until you are sure they are clean.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/preventing-lateral-movement and https://www.ncsc.gov.uk/guidance/assessing-supply-chain-security.  
* Whitelist applications. If supported by your operating environment, consider whitelisting of permitted applications. This will help prevent malicious applications from running.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/eud-security-guidance-windows-10-1709#applicationwhitelistingsection.   
* Manage macros carefully. Disable Microsoft Office macros, except in the specific applications where they are required.  
    Only enable macros for users that need them day-to-day and use a recent and fully patched version of Office and the underlying platform, ideally configured in line with the UK NCSC’s End User Device Security Collection Guidance and UK NCSC’s Macro Security for Microsoft Office Guidance: https://www.ncsc.gov.uk/guidance/end-user-device-security and https://www.ncsc.gov.uk/guidance/macro-security-microsoft-office.  
* Use antivirus. Keep any antivirus software up to date, and consider use of a cloud-backed antivirus product that can benefit from the economies of scale this brings. Ensure that antivirus programs are also capable of scanning Microsoft Office macros.  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST04-005.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/macro-security-microsoft-office.  
* Layer organization-wide phishing defenses. Detect and quarantine as many malicious email attachments and spam as possible, before they reach your end users. Multiple layers of defense will greatly cut the chances of a compromise.  
* Treat people as your first line of defense. Tell personnel how to report suspected phishing emails, and ensure they feel confident to do so. Investigate their reports promptly and thoroughly. Never punish users for clicking phishing links or opening attachments.  
    NCCIC encourages users and administrators to report phishing to phishing-report@us-cert.gov.  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST04-014.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/phishing.   
* Deploy a host-based intrusion detection system. A variety of products are available, free and paid-for, to suit different needs and budgets.  
* Defend your systems and networks against denial-of-service attacks.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/denial-service-dos-guidance-collection.   
* Defend your organization from ransomware. Keep safe backups of important files, protect from malware, and do not pay the ransom– it may not get your data back.  
    See NCCIC Guidance: https://www.us-cert.gov/Ransomware.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/mitigating-malware and https://www.ncsc.gov.uk/guidance/backing-your-data.  
* Make sure you are handling personal data appropriately and securely.  
    See NCCIC Guidance: https://www.us-cert.gov/ncas/tips/ST04-013.  
    See UK NCSC Guidance: https://www.ncsc.gov.uk/guidance/gdpr-security-outcomes.   

(이하 생략 - 각국 기관 연락처 및 사이트 소개이므로 필요시 원문을 보시길 바랍니다.)


