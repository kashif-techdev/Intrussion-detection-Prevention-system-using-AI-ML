# AI-Powered Intrusion Detection and Prevention System (IDS/IPS)

A comprehensive, end-to-end AI-powered intrusion detection and prevention system that combines machine learning with real-time network monitoring.

## 🎯 Project Overview

This system provides:
- **Real-time network traffic analysis** using Zeek/Suricata
- **ML-powered threat detection** with anomaly detection and supervised classification
- **Automated prevention actions** with configurable policies
- **Continuous learning** with feedback loops and retraining
- **SIEM integration** for threat hunting and analyst workflows

## 🏗️ Architecture

```
[Network Taps] → [Packet Capture] → [Feature Extraction] → [ML Inference] → [Decision Engine]
                                                                    ↓
[SIEM/Dashboard] ← [Storage] ← [Prevention Actions] ← [Policy Engine]
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Docker & Docker Compose
- Zeek or Suricata
- Kafka (optional, for production)

### Installation

1. **Clone and setup**:
```bash
git clone <repo-url>
cd ai-ids-ips
pip install -r requirements.txt
```

2. **Start services**:
```bash
docker-compose up -d
```

3. **Run the system**:
```bash
python src/main.py
```

## 📁 Project Structure

```
ai-ids-ips/
├── data/                   # Raw pcaps & datasets
├── features/              # Feature extraction & storage
├── models/                # Trained models & artifacts
├── src/
│   ├── capture/           # Packet capture & parsing
│   ├── fe/               # Feature extraction
│   ├── inference/        # ML model serving
│   ├── decision/         # Decision engine & policies
│   ├── monitoring/       # Logging & metrics
│   └── utils/            # Utilities
├── notebooks/            # Jupyter notebooks for EDA
├── docker/              # Docker configurations
├── infra/               # Infrastructure as code
└── tests/               # Test suites
```

## 🔧 Components

### 1. Data Collection
- **Zeek/Suricata integration** for network monitoring
- **Kafka streaming** for real-time data processing
- **Multiple log formats** support (conn.log, http.log, dns.log)

### 2. Feature Engineering
- **Real-time feature extraction** from network flows
- **Temporal features** with sliding windows
- **Protocol-specific features** (HTTP, DNS, etc.)
- **Statistical aggregations** and anomaly indicators

### 3. Machine Learning
- **Supervised models**: RandomForest, XGBoost, LightGBM
- **Anomaly detection**: IsolationForest, One-Class SVM, Autoencoders
- **Sequence models**: LSTM for flow sequences
- **Ensemble methods** for improved accuracy

### 4. Decision Engine
- **Configurable policies** with threshold tuning
- **Automated blocking** via iptables/NFQUEUE
- **Human-in-the-loop** for critical decisions
- **Safe rollback** mechanisms

### 5. Monitoring & SIEM
- **Real-time dashboards** with Kibana/Grafana
- **Alert management** and analyst workflows
- **Performance metrics** and model drift detection
- **Threat intelligence** integration

## 📊 Datasets

The system supports multiple datasets:
- **CICIDS2017**: Comprehensive intrusion detection dataset
- **UNSW-NB15**: Network-based intrusion detection
- **NSL-KDD**: Improved version of KDD99
- **Bot-IoT**: IoT botnet detection
- **Custom datasets**: Internal network traffic

## 🎯 Performance Metrics

- **Detection Rate**: >95% for known attacks
- **False Positive Rate**: <1% for production use
- **Latency**: <100ms inference time
- **Throughput**: >10K flows/second processing

## 🔒 Security Considerations

- **Data privacy**: Payload sanitization and access controls
- **Adversarial ML**: Robust training and validation
- **Safe defaults**: Conservative blocking policies
- **Audit trails**: Complete decision logging

## 📈 Roadmap

- [x] Phase 0: Project setup & research
- [x] Phase 1: Data collection & baseline IDS
- [x] Phase 2: Feature engineering & datasets
- [x] Phase 3: ML model training
- [x] Phase 4: Real-time inference
- [x] Phase 5: Decision engine & prevention
- [x] Phase 6: Monitoring & SIEM
- [x] Phase 7: Continuous learning

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

For issues and questions:
- Create an issue in the repository
- Check the documentation in `/docs`
- Review the example notebooks in `/notebooks`
