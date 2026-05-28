#!/bin/bash

# Hexa Project Setup Script for Linux (Hangyu's Upgraded Version)

echo "[+] Setting up Hexa Project..."

# 1. Check if Docker is installed
if ! [ -x "$(command -v docker)" ]; then
  echo "Error: docker is not installed. Please install docker first." >&2
  exit 1
fi

if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Error: docker-compose is not installed. Please install docker-compose first." >&2
  exit 1
fi

# 2. Create directories
mkdir -p logs

# 3. [신규 추가] Prometheus 설정 파일 동적 생성
# 우리가 추가한 프로메테우스가 우분투 본체의 Node Exporter(9100)를 바라보게 설정 파일을 자동으로 만듦
echo "[+] Creating prometheus.yml for resource monitoring..."
cat <<EOF > prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ubuntu_host'
    static_configs:
      - targets: ['host.docker.internal:9100', '172.17.0.1:9100']
EOF

# 4. Build and start the containers
echo "[+] Building and starting containers..."
docker-compose up --build -d

echo "------------------------------------------------"
echo "🔥 Hangyu's Active Defense System is now running!"
echo "Website: http://localhost:8080"  # 포트 8080으로 수정됨
echo "IDS/IPS Control Center: http://localhost:4000"
echo "Grafana Dashboard: http://localhost:3000"
echo "------------------------------------------------"