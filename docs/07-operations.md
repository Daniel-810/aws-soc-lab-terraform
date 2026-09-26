# 배포와 운영

| 항목 | 내용 |
|---|---|
| 일자 | 2026-09-26 |
| 관련 | `ADR-007`, `ADR-014`, `ADR-024`, `ADR-032`, `ADR-035`, `ADR-036` |

README의 빠른 실행을 조금 더 자세히 적은 문서다. 처음 배포하는 순서, 검사 방식을 바꾸는 방법, 측정과 검증 도구를 준비하는 방법, 자주 틀리는 지점을 다룬다.

## 1. 준비물

- Terraform 1.10 이상. S3의 자체 잠금(`use_lockfile`)을 쓰기 때문에 잠금용 DynamoDB 테이블은 만들지 않는다.
- AWS CLI v2. 검증 도구가 원격 실행과 로그 조회에 쓴다.
- Python 3. 측정 도구와 검증 도구가 쓴다. 3.12에서 만들고 돌렸다.
- 장기 액세스 키가 아닌 임시 자격증명. 이 저장소는 `aws login`으로 받은 세션에서 MFA 조건이 걸린 역할을 맡아 작업했다(`ADR-014`).

## 2. 처음 한 번

```bash
# 상태 버킷. 로컬 상태로 만들고 그대로 로컬에 둔다
cd bootstrap
terraform init
terraform apply

# 감사 환경. 한 번 만들고 계속 둔다
cd ../envs/audit
cp backend.hcl.example backend.hcl              # 버킷 이름을 실제 값으로
cp terraform.tfvars.example terraform.tfvars    # 예산 알림 받을 주소
terraform init -backend-config=backend.hcl
terraform apply
```

`backend.hcl`과 `terraform.tfvars`는 git에서 제외된다. 버킷 이름에 계정 ID가 들어가고 알림 주소는 개인정보라서 공개 저장소에 올리지 않는다.

감사 환경에는 콘솔에서 먼저 만든 월 예산이 있었다. 새 계정에서는 코드가 예산을 새로 만들고, 예산이 이미 있는 계정이라면 적용하기 전에 가져와야 이름이 겹치지 않는다(`ADR-035`).

```bash
terraform import aws_budgets_budget.monthly <계정 ID>:<예산 이름>
```

로그 버킷은 규정 준수 모드로 하루 동안 잠긴다. 잠긴 동안에는 관리자도 객체를 지울 수 없다. 감사 환경을 지우려면 CloudTrail을 먼저 멈추고, 마지막 로그의 잠금이 풀린 뒤 버킷의 모든 버전을 비워야 한다(`ADR-032`).

## 3. 랩 올리고 내리기

```bash
cd envs/lab
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl

terraform apply                                   # 검사 계층을 만들고 경로는 그대로
terraform apply -var=route_through_firewall=true  # 관리 접속을 확인한 다음 경로를 켠다

terraform destroy -var=route_through_firewall=true
```

랩을 만들 때 `checkip.amazonaws.com`으로 실행하는 장비의 공인 주소를 조회해 웹 방화벽 인바운드에 `/32`로 넣는다. 그래서 배포한 장비에서만 웹 방화벽에 접속할 수 있다(`ADR-019`). 다른 네트워크로 옮겨 가면 주소가 바뀌므로 `apply`를 한 번 더 해야 한다.

Windows PowerShell 5.1에서는 `-이름=값` 형태의 인자를 따옴표로 감싸야 한다. 감싸지 않으면 인자가 쪼개져 「Too many command line arguments」로 실패한다.

```powershell
terraform init "-backend-config=backend.hcl"
terraform apply "-var=route_through_firewall=true"
```

## 4. 검사 방식 고르기

| 변수 | 정하는 것 | 값 | 기본값 |
|---|---|---|---|
| `firewall_mode` | 어느 방식을 만들지 | `managed` (방식 A) / `oss` (방식 B) | `managed` |
| `route_through_firewall` | 트래픽을 검사 계층으로 보낼지 | `true` / `false` | `false` |

```bash
# 방식 B
terraform apply -var=firewall_mode=oss
terraform apply -var=firewall_mode=oss -var=route_through_firewall=true
```

검사 계층을 먼저 만들고 관리 접속을 확인한 다음 경로를 켠다. 두 가지를 한 번에 적용하면 문제가 생겼을 때 정책 탓인지 경로 탓인지 구분할 수 없고, 관리 접속이 끊길 수 있다(`ADR-024`). 앱의 관리 접속도 NAT을 지나 검사 계층을 거치기 때문에, 검사 계층이 443 아웃바운드를 막으면 세션 관리자에 들어갈 방법이 없어진다(`ADR-015`).

Terraform은 지난번에 넘긴 변수를 기억하지 않는다. 방식 B로 배포해 놓고 `-var=firewall_mode=oss`를 빼면 기본값인 방식 A로 읽혀서 Suricata를 지우고 관리형 방화벽을 새로 만드는 계획이 나온다. 계획에 예상하지 않은 삭제가 보이면 변수를 빠뜨린 경우다. 방식을 바꿀 때는 경로부터 끄고 바꾼다. 지금 무엇이 떠 있는지 명령만 보고 알 수 있도록 변수는 파일이 아니라 명령에 적었다.

경로를 켠 직후 수십 초 동안은 인터넷 게이트웨이의 엣지 경로가 아직 반영되지 않아서, 평문 요청이 검사 계층을 거치지 않고 웹 방화벽으로 바로 간다. 이 사이에 측정하면 네트워크 계층의 탐지가 0건으로 나온다. 검증 도구는 이 점검을 최대 90초 동안 다시 시도한다(`ADR-036`).

## 5. 측정과 검증 도구

두 도구는 가상환경 하나를 같이 쓴다. 외부 패키지는 PyYAML 하나이고, HTTP 요청은 표준 라이브러리로 보낸다.

```bash
cd tools/probe
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt      # Windows: .venv\Scripts\python.exe
```

랩이 떠 있고 AWS 자격증명이 설정된 상태에서 실행한다. 검증 도구는 `envs/lab`의 출력값에서 인스턴스 ID와 주소를 읽는다.

```bash
cd tools/verify
../probe/.venv/bin/python verify.py                    # 12개 점검, 약 100초
../probe/.venv/bin/python verify.py --skip-detection   # 탐지 측정을 빼고 빠르게
```

Windows에서는 `.venv/bin/python` 대신 `.venv\Scripts\python.exe`를 쓴다. 점검 목록과 판정 기준은 [`tools/verify/README.md`](../tools/verify/README.md), 측정 도구의 옵션은 [`tools/probe/README.md`](../tools/probe/README.md)에 있다.

측정 결과는 `tools/probe/results/`와 `tools/verify/results/`에 JSON으로 남고 git에서 제외된다. 운영자의 공인 주소와 요청 전문이 들어가기 때문이다.

## 6. 자주 막히는 곳

| 증상 | 원인 | 해결 |
|---|---|---|
| 에러에 `169.254.169.254`가 보인다 | 자격증명을 찾지 못해 EC2 메타데이터까지 내려감 | 셸에서 `AWS_PROFILE`을 다시 지정 |
| 인스턴스 기동이 `Invalid IAM Instance Profile name`으로 실패 | IAM 전파 지연 | 코드를 고치지 말고 다시 `apply` |
| 계획에 검사 계층 삭제가 보인다 | `firewall_mode`를 빠뜨림 | 떠 있는 방식의 변수를 명령에 다시 넣음 |
| 웹 방화벽이 시간 초과 | 운영자 공인 주소가 바뀜 | `apply`를 다시 해 인바운드를 갱신 |
| 평문 공격이 네트워크 계층에서 안 잡힘 | 경로 전환 직후 반영 지연 | 1분쯤 기다렸다 측정 |
| 방식 B 재기동 뒤 앱 관리 명령이 멈춤 | Suricata가 재기동 전에 맺어진 연결을 버림 | 에이전트가 다시 연결할 때까지 기다림 (6분쯤) |

## 7. 비용

랩은 계속 띄워 두지 않고 검증할 때만 만들었다가 지운다. 월 예산은 50,000원이고, 리소스를 만들기 전에 예산 알람부터 걸었다. 이 계정은 크레딧으로 요금을 내고 있어서, 알람은 크레딧을 빼기 전 금액으로 잰다. 크레딧을 뺀 금액으로 재면 실제 사용량이 늘어도 0원으로 보여 알람이 울리지 않는다(`ADR-035`).

관리형 방화벽 엔드포인트가 비용의 대부분이라, 방식 A로 전체를 띄우면 시간당 약 700원, 방식 B는 약 170원이다. 감사 환경과 상태 버킷은 계속 떠 있지만 월 수십 원 수준이다. 서울 리전 온디맨드 단가와 환율 1,400원으로 계산했다.
