# 능동형 서버 자원 관리 및 위협 탐지 시스템

이 프로젝트는 웹 서버의 보안 강화와 실시간 자원 모니터링을 목표로 구축된 **능동형 방어 시스템**입니다. Docker 환경을 기반으로 한 MSA(Microservice Architecture) 구조로 설계되어 있습니다.

## 🛡️ 주요 기능 및 보안 설계

### 1. 웹 방화벽 (WAF) 구축
- **다단계 필터링:** `User-Agent` 분석을 통해 해킹 툴(`Nmap`, `Dirb` 등)을 즉시 차단합니다.
- **악성 패턴 방어:** LFI(경로 탐색), SQL 인젝션, XSS 공격 패턴을 정규식으로 탐지하여 403 Forbidden 응답과 함께 SYSTEM LOCKDOWN 경고를 발생시킵니다.
- **DDoS 방어:** IP별 요청 횟수 제한(Rate Limiting)을 통해 트래픽 폭주로부터 서버를 보호합니다.

### 2. 실시간 위협 관제 연동
- 공격 탐지 시, 즉시 **IDS/IPS 관제 센터(4000번 포트)**로 공격자의 IP와 공격 유형을 API로 보고합니다.
- 능동적인 보안 정책 업데이트를 통해 위협 요소를 실시간으로 차단하는 체계를 갖추었습니다.

### 3. 자원 모니터링 및 시각화
- **Prometheus/Node Exporter:** 시스템의 CPU, 메모리 등 자원 지표를 실시간 수집합니다.
- **Grafana:** 수집된 메트릭을 시각화하여 대시보드로 제공하며, 외부에서도 터널링(`ngrok`)을 통해 접근 가능합니다.

---

## 🛠️ 실행 방법

1. **레포지토리 클론:**
   ```bash
   git clone [https://github.com/wantsurvive/Hexa2.git](https://github.com/wantsurvive/Hexa2.git)
