#!/bin/bash

# AI-Powered IDS/IPS Setup Script
# This script sets up the development environment and installs dependencies

set -e

echo "🚀 Setting up AI-Powered IDS/IPS System..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8+ is required. Current version: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Install development dependencies
echo "🔧 Installing development dependencies..."
pip install -e ".[dev]"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/{raw,processed,captures}
mkdir -p models
mkdir -p logs
mkdir -p features
mkdir -p notebooks

# Set up pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
pre-commit install

# Download sample datasets (if available)
echo "📊 Setting up sample datasets..."
if [ -d "data/sample" ]; then
    echo "✅ Sample data directory already exists"
else
    echo "ℹ️ Sample data directory not found. You can add datasets to data/raw/"
fi

# Create configuration file
echo "⚙️ Creating configuration file..."
if [ ! -f "config.yaml" ]; then
    cat > config.yaml << EOF
# AI-Powered IDS/IPS Configuration

database:
  postgres_url: "postgresql://admin:password123@localhost:5432/ai_ids_ips"
  elasticsearch_url: "http://localhost:9200"
  redis_url: "redis://localhost:6379"

kafka:
  bootstrap_servers: "localhost:9092"
  topics:
    network_logs: "network-logs"
    features: "features"
    alerts: "alerts"
    decisions: "decisions"
  consumer_group: "ai-ids-ips"

model:
  model_path: "models/"
  model_registry_uri: "http://localhost:5000"
  inference_batch_size: 100
  inference_timeout: 1.0

capture:
  interface: "eth0"
  capture_method: "zeek"
  buffer_size: 65536
  timeout: 1.0
  promiscuous: true
  output_dir: "data/captures/"

feature:
  window_size: 60
  feature_store_path: "features/"
  real_time_extraction: true
  batch_size: 1000
  feature_retention_days: 30

decision:
  anomaly_threshold: 0.8
  classification_threshold: 0.7
  auto_block_enabled: false
  auto_block_ttl: 300
  max_blocked_ips: 1000
  whitelist_ips: []
  blacklist_ips: []

monitoring:
  metrics_port: 9090
  log_level: "INFO"
  enable_grafana: true
  enable_prometheus: true

security:
  enable_encryption: true
  enable_audit_logging: true
  max_failed_attempts: 5
  lockout_duration: 300
EOF
    echo "✅ Configuration file created: config.yaml"
else
    echo "✅ Configuration file already exists"
fi

# Run tests
echo "🧪 Running tests..."
python -m pytest tests/ -v

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Start Docker services: docker-compose up -d"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run the system: python src/main.py"
echo "4. View API docs: http://localhost:8000/docs"
echo "5. View metrics: http://localhost:9090/metrics"
echo ""
echo "For more information, see README.md"
