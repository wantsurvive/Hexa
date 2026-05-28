#!/bin/sh
# 파일명: update_ports.sh

ALLOWED_PORTS=$1

if [ -z "$ALLOWED_PORTS" ]; then
  echo "포트 목록이 없습니다."
  exit 1
fi

echo "[인프라 제어] 방화벽 정책 업데이트 시작... 허용 포트: $ALLOWED_PORTS"

# 2. 기존 커스텀 방화벽 룰 초기화
iptables -F HEXA_PORTS 2>/dev/null || iptables -N HEXA_PORTS
iptables -D INPUT -j HEXA_PORTS 2>/dev/null
iptables -I INPUT -j HEXA_PORTS

# 3. 쉼표(,)를 공백으로 바꿔서 쪼개는 표준 방식 (syntax error 완벽 해결)
PORTS=$(echo "$ALLOWED_PORTS" | tr ',' ' ')

for PORT in $PORTS; do
  iptables -A HEXA_PORTS -p tcp --dport "$PORT" -j ACCEPT
  iptables -A HEXA_PORTS -p udp --dport "$PORT" -j ACCEPT
  echo "포트 $PORT 개방 완료"
done

# 4. 허용되지 않은 나머지 차단 룰 (테스트를 위해 주석 해제 상태)
iptables -A HEXA_PORTS -j DROP

echo "방화벽 정책 업데이트 완료!"
