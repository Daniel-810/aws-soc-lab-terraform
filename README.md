# AWS SOC Lab — Terraform 재구성

2025년 콘솔에서 손으로 만들었던 클라우드 보안관제 환경을 Terraform으로 다시 만들었다. 같은 구조를 코드로 옮기면서, 원래 환경을 다시 살펴보다 찾은 결함 16건을 고쳤다.

가장 큰 목적은 네트워크 방화벽을 관리형(AWS Network Firewall)과 직접 운영(EC2 위의 Suricata) 두 가지로 만들고, 같은 요구사항을 만족하는 두 구현이 운영에서 어떻게 다른지 실제로 재 보는 것이었다. 비교의 결론과 근거는 [`docs/06-comparison.md`](docs/06-comparison.md)에 있다.

> 이 환경은 운영용 설계가 아니라 검증용이다. 계층마다 무엇이 보이는지 관찰하려고 일부러 남겨 둔 구성이 있다. 운영 환경과 다른 점과 그 이유는 [`docs/03-architecture.md`](docs/03-architecture.md) 5절에 적었다.

## 결과 요약

| 항목 | 결과 |
|---|---|
| 웹 방화벽 탐지율 | 규칙 집합이 없던 원본 0%에서 44.7%. 앱이 입력을 읽는 위치(질의 문자열, JSON 본문)만 보면 80.1% |
| 실제 사용 흐름 오탐 | 모든 측정에서 0건 |
| 두 방화벽 방식 | 같은 룰로 평문 공격 17건과 16건을 막았고, 판정이 갈린 요청은 1건 |
| 운영 비교 | 관리형은 시간당 약 $0.50에 기동 6분, 직접 운영은 약 $0.12에 기동 2분 |
| 인수 기준 | 11건 모두 충족 ([`docs/05-verification.md`](docs/05-verification.md)) |
| 요구사항 | 46건 중 충족 40, 부분 충족 4, 미구현 2(선택과 권장 항목) |

## 아키텍처

![아키텍처](docs/images/architecture.png)

요청은 인터넷 게이트웨이에서 네트워크 검사 계층을 거쳐 웹 방화벽에 닿고, 웹 방화벽이 TLS를 풀어 검사한 뒤 앱으로 다시 TLS로 보낸다. 앱이 밖으로 나가는 연결도 NAT을 지나 같은 검사 계층을 거친다. 두 방식은 같은 Suricata 엔진에 같은 룰 파일을 써서, 차이가 운영 모델에서만 나오게 했다. 방식은 변수로 고르고 네트워크 구조는 그대로 둔 채 경로의 목적지만 바뀐다. 감사 로그는 랩과 별개로 늘 떠 있는 환경에 있어서 랩을 만들고 지우는 호출까지 기록된다.

## 주요 결과

### 웹 방화벽

원래 환경의 웹 방화벽에는 규칙 집합이 설치되지 않아 탐지 규칙이 0개였다. 요청을 기록만 하고 있었다. 같은 요청 618건을 보내 규칙 집합이 없을 때 0%, CRS 파라노이아 1에서 35.0%, 2에서 44.7%를 확인하고 2로 차단을 켰다. 실제 사용 흐름의 오탐은 모든 단계에서 0건이었다. 요청마다 번호표를 붙여 각 계층의 로그에서 찾는 측정 도구를 직접 만들어서, 차단하지 않는 탐지 전용 상태에서도 몇 건을 잡았는지 셀 수 있었다([`ADR-020`](docs/adr/020-in-house-probe-tool.md), [`ADR-021`](docs/adr/021-record-versions-and-paranoia-level.md)).

### 계층마다 보이는 범위

네트워크 검사 계층은 TLS를 풀기 전에 있어서, 같은 공격을 HTTPS로 보내자 한 건도 잡지 못했다. HTTPS 공격을 막은 것은 전부 웹 방화벽이었다. 네트워크 계층만 할 수 있었던 일은 앱 서버가 밖으로 보내는 요청의 통제였다([`ADR-025`](docs/adr/025-no-firewall-tls-inspection.md)).

### 두 방식

탐지는 거의 같았고 차이는 운영에서 나왔다. 관리형은 비싸고 느리게 뜨지만 전달과 장애 처리를 AWS가 맡는다. 직접 운영은 싸고 빨리 뜨지만, 검사가 멈췄을 때 막는 동작부터 엔진이 룰을 다 읽었는지 확인하는 일까지 직접 만들어야 했다. 대신 설정과 카운터를 볼 수 있어서 이상 동작의 원인을 확인할 수 있었다. 검증용으로 자주 올리고 내리는 환경이면 직접 운영, 계속 띄워 두는 서비스면 관리형이 맞다고 결론 내렸다([`docs/06-comparison.md`](docs/06-comparison.md)).

### 로그

![CloudWatch 대시보드](docs/images/dashboard.png)

방식 B로 측정을 돌린 직후의 대시보드다. 웹 방화벽, IPS, 흐름 로그의 차단 건수와 IPS 경보를 룰과 공격 유형별로 모아 본다. 두 방식의 경보는 필드 이름이 같아서 쿼리 하나로 함께 읽는다([`ADR-030`](docs/adr/030-collection-point-not-siem.md)). 로그 에이전트는 서명을 확인한 뒤에 설치하고, 비밀번호가 담기는 요청 본문은 기록하기 전에 뺀다([`ADR-028`](docs/adr/028-cloudwatch-agent-signature.md), [`ADR-029`](docs/adr/029-mask-before-logging.md)).

## 검증

| 검사 | 언제 | 내용 |
|---|---|---|
| 비밀값 검사 (gitleaks) | 병합 전 필수 | 커밋 이력 전체. 계정 ID가 든 ARN을 잡는 규칙을 따로 둠 |
| 형식, 구문, 모듈 테스트 | 병합 전 필수 | 모듈 테스트 16개가 경로 전환, 공개 범위, IMDSv2, 암호화 같은 결정을 고정 |
| IaC 보안 검사 (Trivy) | 병합 전 필수 | HIGH, CRITICAL이면 병합 불가. 처음 돌렸을 때 세 인스턴스의 디스크가 암호화되지 않은 것을 찾아 고침 |
| 자체 감사 (Prowler) | 배포 후 | 실패 121건 중 계정 설정 11건을 고치고 나머지는 근거를 기록 ([`docs/04-audit-prowler.md`](docs/04-audit-prowler.md)) |
| 배포 검증 (`tools/verify`) | 배포 후 | 손으로 하던 점검 12가지를 명령 하나로. 12개 모두 통과, 약 100초 |

CI는 AWS 자격증명을 쓰지 않는다. 공개 저장소의 CI가 계정에 닿지 않도록 코드만 읽는 검사로 한정했다([`ADR-033`](docs/adr/033-ci-security-gates.md)).

## 문서

| 문서 | 내용 |
|---|---|
| [`01-requirements.md`](docs/01-requirements.md) | 기능 10, 비기능 9, 보안 27, 인수 기준 11, 원본 결함 16건 |
| [`02-threat-model.md`](docs/02-threat-model.md) | 신뢰 경계 5개, 위협 44건, 데이터 흐름도, 받아들인 위험 |
| [`03-architecture.md`](docs/03-architecture.md) | 주소 체계, 라우팅, 보안 그룹, 로그 파이프라인, 운영 환경과의 차이 |
| [`04-audit-prowler.md`](docs/04-audit-prowler.md) | 자체 감사 결과와 조치, 받아들인 항목과 근거 |
| [`05-verification.md`](docs/05-verification.md) | 인수 기준 판정, 요구사항 46건의 추적성 매트릭스, 남은 한계 |
| [`06-comparison.md`](docs/06-comparison.md) | 두 방식 비교와 결론 |
| [`07-operations.md`](docs/07-operations.md) | 배포 순서, 방식 전환, 도구 준비, 자주 막히는 곳, 비용 |
| [`adr/`](docs/adr/) | 설계 결정 36건. 맥락, 결정, 근거, 검토한 대안, 결과 |

설계(요구사항, 위협 모델, 아키텍처)를 먼저 끝내고 구현했다. 위협 모델을 만들다가 아웃바운드 검사 요구사항(`FR-10`)이 빠져 있던 것을 찾아 설계에 넣었다.

## 저장소 구조

```
bootstrap/          상태 버킷. 로컬 상태로 한 번만 실행
envs/
  audit/            늘 떠 있는 감사 환경. CloudTrail, 잠금 버킷, 예산, 계정 기본 설정
  lab/              랩 배포 진입점. 필요할 때 만들고 지운다
modules/
  network/          VPC, 서브넷, 라우팅, 게이트웨이, 보안 그룹
  web/              앱 인스턴스와 내부 TLS 종단
  waf/              웹 방화벽 인스턴스와 규칙 집합
  secrets/          내부 인증 기관 인증서를 전달하는 시크릿
  firewall_managed/ 방식 A. 관리형 방화벽
  firewall_oss/     방식 B. Suricata inline IPS
  observability/    흐름 로그, 지표, 경보, 대시보드
rules/              두 방식이 같이 쓰는 Suricata 룰
scripts/            인스턴스들이 같이 쓰는 설치 스크립트
tools/
  probe/            계층별 탐지 측정 도구
  verify/           배포 검증 스크립트
docs/               설계 문서와 ADR
```

## 빠른 실행

Terraform 1.10 이상과 AWS CLI v2가 필요하다. 상태 버킷(`bootstrap/`)과 감사 환경(`envs/audit/`)을 처음 한 번 만드는 순서, 방식 B로 바꾸는 방법, 검증 도구 준비는 [`docs/07-operations.md`](docs/07-operations.md)에 있다.

```bash
cd envs/lab
cp backend.hcl.example backend.hcl                # 상태 버킷 이름을 채운다
terraform init -backend-config=backend.hcl
terraform apply                                   # 방식 A. 검사 계층만 만들고 경로는 그대로
terraform apply -var=route_through_firewall=true  # 관리 접속을 확인한 뒤 경로를 켠다
terraform destroy -var=route_through_firewall=true
```

배포하는 장비의 공인 주소만 웹 방화벽에 접속할 수 있다. 랩은 쓸 때만 띄운다. 방식 A로 전체를 띄우면 시간당 약 700원, 방식 B는 약 170원이다.
