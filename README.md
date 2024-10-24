# Awesome GPT + Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

GPT 또는 LLM과 함께 사용할 수 있는 보안 도구, 실험적인 사례, 기타 흥미로운 요소들을 엄선하여 모아놓은 리스트입니다.

## 목차

- [도구](#도구)
  - [통합 도구](#통합-도구)
  - [감사](#감사)
  - [정찰](#정찰)
  - [공격](#공격)
  - [탐지](#탐지)
  - [방지](#방지)
  - [사회공학](#사회공학)
  - [리버스 엔지니어링](#리버스-엔지니어링)
  - [조사](#조사)
  - [수정](#수정)
  - [평가](#평가)
- [사례](#사례)
  - [실험](#실험)
  - [학술 연구](#학술-연구)
  - [블로그](#블로그)
  - [재미](#재미)
- [GPT 보안](#gpt-보안)
  - [표준](#표준)
  - [보안 정책 우회](#보안-정책-우회)
  - [버그 바운티](#버그-바운티)
  - [크랙](#크랙)
  - [플러그인 보안](#플러그인-보안)
- [기여하기](#기여하기)

![](./media/aigc.png)

## 주의사항

[이 훌륭한 도구](https://github.com/cckuailong/SuperAdapters)를 사용하여 모든 플랫폼에서 모든 LLM을 모든 어댑터로 미세 조정할 수 있습니다!

## 도구

🧰

### 통합 도구

* [SecGPT](https://github.com/ZacharyZcR/SecGPT) - SecGPT는 LLM을 결합하여 침투 테스트, 레드팀-블루팀 대결, CTF 대회 등 네트워크 보안에 기여하는 것을 목표로 합니다.
* [AutoAudit](https://github.com/ddzipp/AutoAudit) - 사이버 보안을 위한 LLM입니다.
* [secgpt](https://github.com/Clouditera/secgpt) - baichuan-13B와 함께 Lora로 미세 조정된 사이버 보안용 LLM입니다.
* [HackerGPT-2.0](https://github.com/Hacker-GPT/HackerGPT-2.0) - 해킹 세계에서 없어서는 안 될 디지털 동반자입니다.

### 감사

* [SourceGPT](https://github.com/NightmareLab/SourceGPT) - ChatGPT를 사용한 프롬프트 관리자이자 소스 코드 분석 도구입니다.
* [ChatGPTScanner](https://github.com/YulinSec/ChatGPTScanner) - ChatGPT로 구동되는 화이트박스 코드 스캔 도구입니다.
* [chatgpt-code-analyzer](https://github.com/MilindPurswani/chatgpt-code-analyzer) - Visual Studio Code용 ChatGPT 코드 분석기입니다.
* [hacker-ai](https://hacker-ai.ai/#hacker-ai) - 소스 코드의 취약점을 탐지하는 AI 기반 온라인 도구입니다.
* [audit_gpt](https://github.com/fuzzland/audit_gpt) - 스마트 계약 감사용으로 GPT를 미세 조정한 도구입니다.
* [vulchatgpt](https://github.com/ke0z/vulchatgpt) - IDA PRO HexRays 디컴파일러와 OpenAI(ChatGPT)를 사용하여 바이너리에서 취약점을 찾아냅니다.
* [Ret2GPT](https://github.com/DDizzzy79/Ret2GPT) - OpenAI의 LangChain 기술을 활용하여 CTF Pwner의 바이너리 파일 해석과 취약점 탐지를 혁신하는 고급 AI 기반 바이너리 분석 도구입니다.

### 정찰

* [CensysGPT Beta](https://gpt.censys.io) - 인터넷 상의 호스트에 대한 정보를 빠르고 쉽게 얻을 수 있도록 해주는 도구로, 위협 사냥과 노출 관리 과정을 간소화합니다.
* [GPT_Vuln-analyzer](https://github.com/morpheuslord/GPT_Vuln-analyzer) - ChatGPT API, Python-Nmap, DNS Recon 모듈을 사용하여 Nmap 스캔 데이터 및 DNS 스캔 정보를 바탕으로 취약점 보고서를 생성합니다. 또한 하위 도메인 열거도 수행할 수 있습니다.
* [SubGPT](https://github.com/s0md3v/SubGPT) - 이미 발견한 도메인의 하위 도메인을 BingGPT를 사용해 더 많이 찾습니다.
* [Navi](https://github.com/SSGOrg/Navi) - GPT를 활용한 QA 기반 정찰 도구입니다.
* [ChatCVE](https://github.com/jasona7/ChatCVE) - CVE(공통 취약점 및 노출) 정보를 트리아지하고 집계하기 위한 AI 기반 devSecOps 애플리케이션입니다.
* [ZoomeyeGPT](https://github.com/knownsec/ZoomeyeGPT) - ZoomEye 사용자에게 AI 지원 검색 경험을 제공하기 위한 GPT 기반 크롬 브라우저 확장 프로그램입니다.
* [uncover-turbo](https://github.com/zt2/uncover-turbo) - 범용 자연어 조사 및 매핑 엔진을 구현하여 자연어에서 조사 및 매핑 구문으로의 마지막 마일을 엽니다.
* [DevOpsGPT](https://github.com/kuafuai/DevOpsGPT) - AI 기반 소프트웨어 개발 자동화 솔루션입니다.

### 공격

* [PentestGPT](https://github.com/GreyDGL/PentestGPT) - GPT를 활용한 침투 테스트 도구입니다.
* [burpgpt](https://github.com/aress31/burpgpt) - OpenAI의 GPT와 통합된 Burp Suite 확장으로 맞춤형 취약점을 추가로 발견하는 수동 스캔을 수행하고, 모든 유형의 트래픽 기반 분석을 실행할 수 있습니다.
* [ReconAIzer](https://github.com/hisxo/ReconAIzer) - Bug Bounty 정찰을 위해 OpenAI(GPT)를 Burp에 추가하는 Burp Suite 확장입니다. 엔드포인트, 매개변수, URL, 하위 도메인 등을 발견하는 데 도움을 줍니다.
* [CodaMOSA](https://github.com/microsoft/codamosa) - OpenAI API와 결합하여 전통적인 퍼징에서 커버리지 정체 문제를 완화하는 퍼저를 구현한 논문의 코드입니다.
* [PassGAN](https://github.com/brannondorsey/PassGAN) - 비밀번호 추측을 위한 딥 러닝 접근법입니다. [HomeSecurityHeroes 제품](https://www.homesecurityheroes.com/ai-password-cracking/)에서는 AI가 비밀번호를 크랙하는 데 필요한 시간을 테스트할 수 있습니다.
* [nuclei-ai-extension](https://github.com/projectdiscovery/nuclei-ai-extension) - Nuclei 팀이 공식적으로 제공하는 브라우저 확장으로, 빠른 Nuclei 템플릿 생성을 지원합니다.
* [nuclei_gpt](https://github.com/sf197/nuclei_gpt) - 관련된 요청과 응답 및 취약점 설명을 제출하여 Nuclei PoC를 생성할 수 있습니다.
* [Nuclei Templates AI Generator](https://templates.nuclei.sh/) - 텍스트 설명으로 Nuclei 템플릿을 생성하는 도구입니다 (예: PoC에 의한 취약점 스캐너).
* [hackGPT](https://github.com/NoDataFound/hackGPT) - OpenAI 및 ChatGPT를 활용하여 해커 같은 작업을 수행합니다.

### 탐지

* [k8sgpt](https://github.com/k8sgpt-ai/k8sgpt/) - Kubernetes 클러스터를 스캔하고 문제를 진단하며 간단한 영어로 트리아지하는 도구입니다.
* [cloudgpt](https://github.com/ustayready/cloudgpt) - ChatGPT를 활용하여 AWS 고객 관리 정책의 취약점을 스캔하는 도구입니다.
* [IATelligence](https://github.com/fr0gger/IATelligence) - PE 파일의 IAT를 추출하여 GPT에게 API와 ATT&CK 매트릭스에 대한 정보를 요청하는 파이썬 스크립트입니다.
* [rebuff](https://github.com/protectai/rebuff) - 프롬프트 인젝션 탐지 도구입니다.
* [Callisto](https://github.com/JetP1ane/Callisto) - AI 기반의 바이너리 취약점 분석 도구입니다.
* [LLMFuzzer](https://github.com/mnns/LLMFuzzer) - LLM API 통합을 통해 대형 언어 모델(LLM)을 위한 최초의 오픈 소스 퍼징 프레임워크입니다.
* [Vigil](https://github.com/deadbits/vigil-llm) - 프롬프트 인젝션 탐지 및 LLM 프롬프트 보안 스캐너입니다.

### 방지

(아직 추가되지 않았습니다.)

### 사회공학

* [ChatGPT-Web-Setting-Funny-Abuse](https://github.com/Esonhugh/ChatGPT-Web-Setting-Funny-Abuse) - ChatGPT 웹을 재미있게 다루며 HTML 렌더링을 설정에서 발견합니다.

### 리버스 엔지니어링

* [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) - 대형 언어 모델을 사용하여 바이너리 코드를 디컴파일합니다.
* [Gepetto](https://github.com/JusticeRage/Gepetto) - OpenAI의 gpt-3.5-turbo 언어 모델을 쿼리하여 리버스 엔지니어링 속도를 높이는 IDA 플러그인입니다.
* [gpt-wpre](https://github.com/moyix/gpt-wpre) - GPT-3을 사용한 전체 프로그램 리버스 엔지니어링입니다.
* [G-3PO](https://github.com/tenable/ghidra_tools/tree/main/g3po) - 디컴파일된 코드에 대해 GPT-3의 주석을 요청하는 스크립트입니다.

### 조사

* [beelzebub](https://github.com/mariocandela/beelzebub) - Go 기반 저코드 허니팟 프레임워크로, GPT-3을 활용한 시스템 가상화 기능을 갖추고 있습니다.

### 수정

* [wolverine](https://github.com/biobootloader/wolverine) - Python 스크립트/코드의 버그를 자동으로 수정합니다.

### 평가

* [falco-gpt](https://github.com/Dentrax/falco-gpt) - Falco 감사 이벤트에 대한 AI 생성 개선 사항을 제공합니다.
* [selefra](https://github.com/selefra/selefra) - 멀티 클라우드 및 SaaS 분석을 제공하는 오픈 소스 정책 코드 소프트웨어입니다.
* [openai-cti-summarizer](https://github.com/EC-DIGIT-CSIRC/openai-cti-summarizer) - OpenAI의 GPT-3.5 및 GPT-4 API를 기반으로 위협 인텔리전스 요약 보고서를 생성하는 도구입니다.

---
## 사례

🌰

### 실험

* [ChatGPT-3.5의 메모리 문제에서 벗어나 CVE PoC 작성](https://tin-z.github.io/chatgpt/go/cve/2023/04/14/escaping_chatgpt_memory.html)
* [ChatGPT 프롬프트만으로 탐지가 불가능한 제로데이 바이러스 만들기](https://www.forcepoint.com/blog/x-labs/zero-day-exfiltration-using-chatgpt-prompts)
* [코드의 보안 취약점 탐지를 위한 GPT-3 실험](https://github.com/chris-koch-penn/gpt3_security_vulnerability_scanner)
* [GPT-4를 Semgrep에 넣어 오탐 제거 및 코드 수정](https://semgrep.dev/blog/2023/gpt4-and-semgrep-detailed)
* [ChatGPT를 사용한 실용적인 AI 기반 피싱 PoC](https://curtbraz.medium.com/a-practical-ai-generated-phishing-poc-f81d3c3da76b)
* [GPT-4로 플래그 캡처하기](https://micahflee.com/2023/04/capturing-the-flag-with-gpt-4/)
* [단일 코드베이스에서 213개의 보안 취약점을 찾아낸 GPT-3 사용 사례](https://betterprogramming.pub/i-used-gpt-3-to-find-213-security-vulnerabilities-in-a-single-codebase-cc3870ba9411)
* [인코더 및 WebShell 지원을 위한 ChatGPT 생성](https://mp.weixin.qq.com/s/I9IhkZZ3YrxblWIxWMXAWA)
* [피싱 캠페인 생성을 위한 OpenAI Chat 사용](https://www.richardosgood.com/posts/using-openai-chat-for-phishing/) -- 피싱 플랫폼 포함
* [Chat4GPT 보안 실험](https://github.com/mesutgungor/ChatGPT4Security)
* [사이버 보안을 위한 GPT-3 사용 사례](https://github.com/sophos/gpt3-and-cybersecurity)
* [AI 기반 퍼징: 버그 헌팅 장벽 돌파하기](https://security.googleblog.com/2023/08/ai-powered-fuzzing-breaking-bug-hunting.html)

### 학술 연구

* [GPT-4 기술 보고서](https://arxiv.org/abs/2303.08774) - OpenAI의 자체 보안 평가 및 모델 완화
* [이전 프롬프트 무시하기: 언어 모델에 대한 공격 기술](https://arxiv.org/pdf/2211.09527.pdf) - 프롬프트 인젝션의 선구적인 연구
* [당신이 요청한 것보다 더 많이: 애플리케이션 통합 대형 언어 모델에 대한 새로운 프롬프트 인젝션 위협에 대한 포괄적인 분석](https://arxiv.org/abs/2302.12173)
* [RealToxicityPrompts: 언어 모델의 신경 독성 퇴행 평가](https://arxiv.org/pdf/2009.11462.pdf)
* [LLM의 프로그래밍적 행동 악용: 표준 보안 공격을 통한 이중 사용](https://arxiv.org/pdf/2302.05733.pdf)
* [언어 모델의 피해를 줄이기 위한 레드팀 훈련: 방법, 확장 행동 및 교훈](https://arxiv.org/pdf/2209.07858.pdf)
* [자연어로 쉘코드를 생성할 수 있을까? 경험적 연구](https://link.springer.com/article/10.1007/s10515-022-00331-3)

### 블로그

* [ChatGPT를 보조 도구로 사용하여 Redis CVE-2023-28425 분석하기](https://tin-z.github.io/redis/cve/chatgpt/2023/04/02/redis-cve2023.html)
* [ChatGPT를 활용한 보안 코드 리뷰](https://research.nccgroup.com/2023/02/09/security-code-review-with-chatgpt/)
* [랜섬웨어 작성을 기꺼이 하는 ChatGPT, 다만 실력이 좋지는 않다](https://www.malwarebytes.com/blog/news/2023/03/chatgpt-happy-to-write-ransomware-just-really-bad-at-it?utm_source=blueshift&utm_medium=email&utm_campaign=b2c_pro_oth_20230403_aprilweeklynewsletter_v1_168025968119&utm_content=chatgpt_ransomware)
* [ATT&CK 그룹 지식 기반 생성하기](https://otrf.github.io/GPT-Security-Adventures/experiments/ATTCK-GPT/notebook.html)
* [모델 혼란 - 레드팀과 버그 헌터를 위한 ML 모델 무기화](https://5stars217.github.io/2023-08-08-red-teaming-with-ml-models/)
* [LLM을 사용하여 자바스크립트 변수명 축소 해제하기](https://thejunkland.com/blog/using-llms-to-reverse-javascript-minification)

### 재미

* [비밀 키를 보호할 수 있는 가장 짧은 프롬프트](https://gpd.43z.one/)
* [언어 해킹을 통해 LLM을 우회하는 방법을 배우는 CTF 유사 게임](https://doublespeak.chat/#/)
* [ai-goat](https://github.com/dhammon/ai-goat) - 취약한 LLM CTF 도전을 통해 AI 보안을 학습합니다.

---
## GPT 보안

🚨

### 표준

* [LLM 앱을 위한 ATT&CK](https://atlas.mitre.org/)
* [대형 언어 모델 애플리케이션을 위한 OWASP Top 10 프로젝트](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [Google AI 레드팀](https://services.google.com/fh/files/blogs/google_ai_red_team_digital_final.pdf)
* [PurpleLlama](https://github.com/facebookresearch/PurpleLlama) - 개발자에게 힘을 실어주고 안전성을 높이며 열린 생태계를 구축합니다.
* [agentic_security](https://github.com/msoedov/agentic_security) - 에이전틱 LLM 취약점 스캐너입니다.
* [garak](https://github.com/leondz/garak) - LLM 취약점 스캐너입니다.
* [inspect_ai](https://github.com/UKGovernmentBEIS/inspect_ai) - 대형 언어 모델 평가를 위한 프레임워크입니다.

### 보안 정책 우회

* [Chat GPT "DAN" (및 기타 "탈옥" 기법)](https://gist.github.com/coolaj86/6f4f7b30129b0251f61fa7baaa881516)
* [버그 바운티 및 침투 테스트를 위한 ChatGPT 프롬프트](https://github.com/TakSec/chatgpt-prompts-bug-bounty)
* [promptmap](https://github.com/utkusen/promptmap) - ChatGPT 인스턴스에 대한 프롬프트 인젝션 공격을 자동으로 테스트합니다.
* [Typoglycemia를 사용하여 LLM의 보안 정책 우회하기](https://mp.weixin.qq.com/s?__biz=MzkwNDI1NDUwMQ==&mid=2247486630&idx=1&sn=814af2fb7a06e5283b026c6483c47b07)
* [정렬된 언어 모델에 대한 보편적이고 전이 가능한 적대적 공격](https://llm-attacks.org/)
* [promptbench](https://github.com/microsoft/promptbench) - 대형 언어 모델의 악의적인 프롬프트에 대한 강건성 평가 프레임워크입니다.

### 버그 바운티

* [ChatGPT 내에 가상 머신 구축하기](https://www.engraved.blog/building-a-virtual-machine-inside/) - 더 이상 지원되지 않지만 흥미로운 내용입니다.
* [LangChain의 코드 인젝션 취약점 -- CVE-2023-29374](https://github.com/advisories/GHSA-fprp-p869-w6q2)

### 크랙

* [gpt4free](https://github.com/xtekky/gpt4free) - 다양한 언어 모델 사이트의 API를 모은 저장소입니다.
* [EdgeGPT](https://github.com/acheong08/EdgeGPT) - Microsoft의 Bing Chat AI의 역설계 API입니다.
* [GPTs](https://github.com/linexjlin/GPTs) - 유출된 GPT 프롬프트들입니다.

### 플러그인 보안

* [SecureGPT](https://escape.tech/securegpt) - ChatGPT 플러그인 API의 보안을 동적으로 테스트하는 도구입니다 (ChatGPT 플러그인용 무료 DAST).

# 기여하기

기여는 언제나 환영합니다! 먼저 [기여 가이드라인](https://github.com/cckuailong/awesome-gpt-security/blob/master/CONTRIBUTING.md)을 확인해주세요.

- - -

이 의견 리스트에 대해 질문이 있으시면 GitHub에 이슈를 열어주세요.

<p align="center">
<a href="https://github.com/cckuailong/awesome-gpt-security/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=cckuailong/awesome-gpt-security&max=100">
</a>
</p>

기여해주셔서 감사합니다. 커뮤니티를 활기차게 유지하는 데 큰 힘이 됩니다. :heart:

