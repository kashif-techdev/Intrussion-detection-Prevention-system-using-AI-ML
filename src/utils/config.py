"""
Configuration management for the AI-powered IDS/IPS system.
Handles environment variables, default settings, and configuration validation.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
import yaml
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    postgres_url: str = field(default_factory=lambda: os.getenv("POSTGRES_URL", "postgresql://admin:password123@localhost:5432/ai_ids_ips"))
    elasticsearch_url: str = field(default_factory=lambda: os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"))
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379"))
    influxdb_url: str = field(default_factory=lambda: os.getenv("INFLUXDB_URL", "http://localhost:8086"))


@dataclass
class KafkaConfig:
    """Kafka configuration settings."""
    bootstrap_servers: str = field(default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    topics: Dict[str, str] = field(default_factory=lambda: {
        "network_logs": "network-logs",
        "features": "features",
        "alerts": "alerts",
        "decisions": "decisions"
    })
    consumer_group: str = "ai-ids-ips"
    auto_offset_reset: str = "latest"


@dataclass
class ModelConfig:
    """ML model configuration settings."""
    model_path: str = field(default_factory=lambda: os.getenv("MODEL_PATH", "models/"))
    model_registry_uri: str = field(default_factory=lambda: os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000"))
    inference_batch_size: int = 100
    inference_timeout: float = 1.0
    model_update_interval: int = 3600  # seconds


@dataclass
class CaptureConfig:
    """Packet capture configuration settings."""
    interface: str = field(default_factory=lambda: os.getenv("CAPTURE_INTERFACE", "eth0"))
    capture_method: str = field(default_factory=lambda: os.getenv("CAPTURE_METHOD", "zeek"))  # zeek, suricata, scapy
    buffer_size: int = 65536
    timeout: float = 1.0
    promiscuous: bool = True
    output_dir: str = field(default_factory=lambda: os.getenv("CAPTURE_OUTPUT_DIR", "data/captures/"))


@dataclass
class FeatureConfig:
    """Feature extraction configuration settings."""
    window_size: int = 60  # seconds
    feature_store_path: str = field(default_factory=lambda: os.getenv("FEATURE_STORE_PATH", "features/"))
    real_time_extraction: bool = True
    batch_size: int = 1000
    feature_retention_days: int = 30


@dataclass
class DecisionConfig:
    """Decision engine configuration settings."""
    anomaly_threshold: float = 0.8
    classification_threshold: float = 0.7
    auto_block_enabled: bool = False
    auto_block_ttl: int = 300  # seconds
    max_blocked_ips: int = 1000
    whitelist_ips: List[str] = field(default_factory=list)
    blacklist_ips: List[str] = field(default_factory=list)


@dataclass
class MonitoringConfig:
    """Monitoring and metrics configuration settings."""
    metrics_port: int = 9090
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    enable_grafana: bool = True
    enable_prometheus: bool = True
    alert_webhook_url: Optional[str] = field(default_factory=lambda: os.getenv("ALERT_WEBHOOK_URL"))


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    enable_encryption: bool = True
    encryption_key: Optional[str] = field(default_factory=lambda: os.getenv("ENCRYPTION_KEY"))
    enable_audit_logging: bool = True
    max_failed_attempts: int = 5
    lockout_duration: int = 300  # seconds


class Config:
    """Main configuration class that aggregates all configuration sections."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_file: Optional path to YAML configuration file
        """
        self.database = DatabaseConfig()
        self.kafka = KafkaConfig()
        self.model = ModelConfig()
        self.capture = CaptureConfig()
        self.feature = FeatureConfig()
        self.decision = DecisionConfig()
        self.monitoring = MonitoringConfig()
        self.security = SecurityConfig()
        
        # Load from file if provided
        if config_file and Path(config_file).exists():
            self.load_from_file(config_file)
        
        # Validate configuration
        self.validate()
    
    def load_from_file(self, config_file: str):
        """Load configuration from YAML file.
        
        Args:
            config_file: Path to YAML configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update configuration sections
            for section_name, section_data in config_data.items():
                if hasattr(self, section_name):
                    section = getattr(self, section_name)
                    for key, value in section_data.items():
                        if hasattr(section, key):
                            setattr(section, key, value)
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_file}: {e}")
    
    def validate(self):
        """Validate configuration settings."""
        errors = []
        
        # Validate required fields
        if not self.database.postgres_url:
            errors.append("Database PostgreSQL URL is required")
        
        if not self.kafka.bootstrap_servers:
            errors.append("Kafka bootstrap servers are required")
        
        if self.decision.anomaly_threshold < 0 or self.decision.anomaly_threshold > 1:
            errors.append("Anomaly threshold must be between 0 and 1")
        
        if self.decision.classification_threshold < 0 or self.decision.classification_threshold > 1:
            errors.append("Classification threshold must be between 0 and 1")
        
        if self.security.enable_encryption and not self.security.encryption_key:
            errors.append("Encryption key is required when encryption is enabled")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "database": self.database.__dict__,
            "kafka": self.kafka.__dict__,
            "model": self.model.__dict__,
            "capture": self.capture.__dict__,
            "feature": self.feature.__dict__,
            "decision": self.decision.__dict__,
            "monitoring": self.monitoring.__dict__,
            "security": self.security.__dict__
        }
    
    def save_to_file(self, config_file: str):
        """Save configuration to YAML file.
        
        Args:
            config_file: Path to save configuration file
        """
        try:
            with open(config_file, 'w') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)
        except Exception as e:
            raise ValueError(f"Failed to save configuration to {config_file}: {e}")


# Global configuration instance
config = Config()
