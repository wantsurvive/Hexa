# IDS/IPS Frontend Prototype (HTML/CSS/JS)

TODO 문서를 기반으로 만든 단일 페이지 IDS/IPS 시뮬레이터입니다.

## 실행 방법
1. 백엔드 서버 실행

PowerShell 예시:
```powershell
cd ./Desktop/Hexa/IDSIPS
npm install
npm start
```

2. 브라우저 접속
- http://localhost:4000

3. 프론트엔드를 별도 포트(예: 5500)에서 여는 경우
- 같은 호스트에서 열리면 API를 자동으로 찾습니다.
- 다른 호스트나 파일로 열 경우에는 `?apiBase=http://서버IP:4000` 형태로 백엔드 주소를 지정할 수 있습니다.

## 구현 범위
- 서버 자원 대시보드(전체 + IP별)
- 수동 IP 차단/해제
- 자동 차단
  - 자원 사용량 10% 이상 감지
  - 포트 스캔(짧은 시간 내 scanCount 증가) 감지
- 관리자 인허가 워크플로우
- 로그 수집
  - 전체 로그
  - 의심 로그 분리
- 방화벽 정책
  - 허용 포트 정책/불필요 포트 닫기
  - 권한/핵심 파일 변경 시도 이벤트 시 세션 종료(엔진 OFF 전환)
  - 관리자 IP 차단 예외
- HTTP -> HTTPS 강제 체크(로컬 제외)
- SSL 만료일 모니터링(경보)
- IDS/IPS ON/OFF 토글 및 상태 복원(LocalStorage)

## 파일 구성
- `src/index.html`: UI 레이아웃
- `src/styles/main.css`: 스타일 및 반응형 UI
- `src/js/app.js`: 상태 관리, 탐지/차단, 로그, 방화벽 로직
- `TODO.md`: 요구사항 원본

## 참고
브라우저 단독 환경 특성상 실제 OS 방화벽/프로세스 종료/인증서 자동 갱신은 시뮬레이션 방식으로 구현했습니다.
운영 환경에서는 백엔드/시스템 레벨 모듈(예: Node.js + 방화벽 API + 로그 파이프라인)과 연결이 필요합니다.
