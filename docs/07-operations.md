# 배포와 운영

| 항목 | 내용 |
|---|---|
| 일자 | 2026-09-26 |
| 관련 | `ADR-007`, `ADR-014`, `ADR-024`, `ADR-032`, `ADR-035`, `ADR-036` |

README의 빠른 시작을 자세히 풀어 쓴 문서다. 처음 배포하는 순서, 검사 방식 바꾸기, 측정 도구와 점검 도구 준비, 그리고 자주 막히는 곳을 적었다.

## 1. 준비물

- Terraform 1.10 이상. 상태 잠금에 S3 자체 잠금 파일(`use_lockfile`)을 쓰므로 DynamoDB 테이블은 필요 없다.
- AWS CLI v2. 점검 도구가 원격 명령과 로그 조회에 쓴다.
- Python 3. 측정 도구와 점검 도구에 쓴다. 3.12에서 개발하고 실행했다.
- 오래 쓰는 액세스 키 대신 임시 자격 증명. 이 저장소는 `aws login`으로 받은 세션에서 MFA가 필요한 역할을 맡아 만들었다(`ADR-014`).

## 2. 처음 한 번만 하는 설정

```bash
# 상태 버킷. 로컬 상태로 만들고, 상태 파일도 로컬에 그대로 둔다
cd bootstrap
terraform init
terraform apply

# 감사 환경. 한 번 만들고 계속 켜 둔다
cd ../envs/audit
cp backend.hcl.example backend.hcl              # 실제 버킷 이름을 넣는다
cp terraform.tfvars.example terraform.tfvars    # 예산 알림 받을 주소
terraform init -backend-config=backend.hcl
terraform apply
```

`backend.hcl`과 `terraform.tfvars`는 git에서 뺐다. 버킷 이름에는 계정 ID가, 알림 주소에는 개인정보가 들어 있어서 공개 저장소에 올리지 않는다.

감사 환경은 처음에 콘솔에서 만들었던 월 예산도 관리한다. 새 계정이라면 코드가 예산을 만든다. 계정에 이미 예산이 있다면 이름이 겹치지 않도록 apply 전에 가져온다(`ADR-035`).

```bash
terraform import aws_budgets_budget.monthly <account-id>:<budget-name>
```

로그 버킷은 컴플라이언스 모드 Object Lock을 하루 동안 건다. 잠긴 객체는 관리자도 지울 수 없다. 감사 환경을 없애려면 CloudTrail을 먼저 멈추고, 마지막 로그의 잠금이 풀릴 때까지 기다린 다음, 버킷의 모든 버전을 비워야 한다(`ADR-032`).

## 3. 랩 올리고 내리기

```bash
cd envs/lab
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl

terraform apply                                   # 검사 계층 생성, 라우팅은 그대로
terraform apply -var=route_through_firewall=true  # 관리 접속을 확인한 뒤 라우팅 전환

terraform destroy -var=route_through_firewall=true
```

apply할 때 랩은 `checkip.amazonaws.com`에서 배포하는 컴퓨터의 공인 IP를 알아내 WAF 인바운드 규칙에 `/32`로 허용한다. 그래서 그 컴퓨터만 WAF에 접근할 수 있다(`ADR-019`). 다른 네트워크로 옮기면 주소가 바뀌므로 다시 apply해야 한다.

Windows PowerShell 5.1에서는 `-이름=값` 형태의 인자를 따옴표로 감싸야 한다. 감싸지 않으면 인자가 쪼개져서 Terraform이 "Too many command line arguments" 오류를 낸다.

```powershell
terraform init "-backend-config=backend.hcl"
terraform apply "-var=route_through_firewall=true"
```

## 4. 검사 방식 고르기

| 변수 | 정하는 것 | 값 | 기본값 |
|---|---|---|---|
| `firewall_mode` | 어느 방식을 만들지 | `managed`(방식 A) / `oss`(방식 B) | `managed` |
| `route_through_firewall` | 트래픽을 검사 계층으로 보낼지 | `true` / `false` | `false` |

```bash
# 방식 B
terraform apply -var=firewall_mode=oss
terraform apply -var=firewall_mode=oss -var=route_through_firewall=true
```

검사 계층을 먼저 만들고, 관리 접속을 확인한 다음, 라우팅을 바꾼다. 둘을 한 번에 apply했다가 문제가 생기면 정책 탓인지 라우팅 탓인지 알 수 없고, 관리 접속까지 잃을 수 있다(`ADR-024`). 앱의 관리 트래픽도 NAT와 검사 계층을 지나기 때문에, 검사 계층이 밖으로 나가는 443을 막으면 Session Manager로 들어갈 길이 사라진다(`ADR-015`).

Terraform은 이전에 넘긴 변수를 기억하지 않는다. 방식 B를 배포해 둔 상태에서 `-var=firewall_mode=oss`를 빼먹으면, Terraform은 기본값인 방식 A로 읽고 Suricata를 지우고 관리형 방화벽을 만드는 계획을 세운다. plan에 예상하지 못한 삭제가 보이면 변수를 빠뜨린 것이다. 방식을 바꿀 때는 라우팅부터 끈다. 변수를 파일이 아니라 명령줄로 넘기는 이유는, 명령만 봐도 무엇이 돌고 있는지 알 수 있게 하려는 것이다.

라우팅을 켠 뒤 수십 초 동안은 인터넷 게이트웨이의 엣지 라우팅이 아직 적용되지 않아서, 평문 요청이 검사 계층을 거치지 않고 WAF로 바로 간다. 이때 측정하면 네트워크 계층 탐지가 0건으로 나온다. 점검 도구는 이 점검을 최대 90초까지 다시 시도한다(`ADR-036`).

## 5. 측정 도구와 점검 도구

두 도구는 가상 환경 하나를 함께 쓴다. 외부 패키지는 PyYAML 하나뿐이고, HTTP 요청은 표준 라이브러리로 보낸다.

```bash
cd tools/probe
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt      # Windows: .venv\Scripts\python.exe
```

랩이 떠 있고 AWS 자격 증명이 설정된 상태에서 실행한다. 점검 도구는 인스턴스 ID와 주소를 `envs/lab`의 출력값에서 읽는다.

```bash
cd tools/verify
../probe/.venv/bin/python verify.py                    # 점검 12개, 약 100초
../probe/.venv/bin/python verify.py --skip-detection   # 탐지 측정을 빼고 빠르게
```

Windows에서는 `.venv/bin/python` 대신 `.venv\Scripts\python.exe`를 쓴다. 점검 목록과 통과 기준은 [`tools/verify/README.md`](../tools/verify/README.md)에, 측정 도구의 옵션은 [`tools/probe/README.md`](../tools/probe/README.md)에 있다.

결과는 `tools/probe/results/`와 `tools/verify/results/`에 JSON으로 쌓이고, git에서는 뺐다. 운영자의 공인 IP와 요청 내용이 그대로 들어 있기 때문이다.

## 6. 자주 막히는 곳

| 증상 | 원인 | 해결 |
|---|---|---|
| 오류 메시지에 `169.254.169.254`가 나온다 | 자격 증명을 찾지 못해 SDK가 EC2 인스턴스 메타데이터까지 내려갔다 | 셸에서 `AWS_PROFILE`을 다시 설정한다 |
| 인스턴스 생성이 `Invalid IAM Instance Profile name`으로 실패한다 | IAM 반영 지연 | 코드는 고치지 말고 `apply`를 다시 실행한다 |
| plan이 검사 계층을 지우려 한다 | `firewall_mode`를 빠뜨렸다 | 지금 돌고 있는 방식의 변수를 넘긴다 |
| WAF 접속이 시간 초과된다 | 공인 IP가 바뀌었다 | `apply`를 다시 실행해 인바운드 규칙을 갱신한다 |
| 네트워크 계층에서 평문 공격이 안 잡힌다 | 라우팅을 바꾼 직후라 엣지 라우팅이 아직 적용되지 않았다 | 1분쯤 기다렸다가 측정한다 |
| Suricata를 다시 시작한 뒤 앱에 보낸 명령이 멈춘다(방식 B) | 다시 시작하기 전에 맺어진 연결을 Suricata가 버린다 | 에이전트가 다시 연결될 때까지 기다린다(약 6분) |

## 7. 비용

랩은 켜 두지 않는다. 시험할 때 만들고 끝나면 지운다. 월 예산은 5만 원이고, 예산 알람은 리소스를 하나도 만들기 전에 먼저 걸었다. 이 계정은 크레딧으로 결제하기 때문에, 알람은 크레딧을 빼기 전 비용을 기준으로 한다. 크레딧을 뺀 뒤 금액으로 재면 사용량이 늘어도 지출이 0으로 보여서 알람이 영영 울리지 않는다(`ADR-035`).

비용의 대부분은 관리형 방화벽 엔드포인트다. 방식 A로 전부 켜면 시간당 약 $0.50, 방식 B는 약 $0.12가 든다. 감사 환경과 상태 버킷은 계속 떠 있지만 한 달에 몇 센트밖에 들지 않는다. 금액은 서울 리전 온디맨드 단가 기준이다.
