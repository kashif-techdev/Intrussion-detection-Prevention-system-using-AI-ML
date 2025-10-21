"""
Basic tests for the AI-powered IDS/IPS system.
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.utils.config import Config
from src.utils.logger import get_logger


def test_config_loading():
    """Test configuration loading."""
    config = Config()
    
    # Test basic configuration sections
    assert hasattr(config, 'database')
    assert hasattr(config, 'kafka')
    assert hasattr(config, 'model')
    assert hasattr(config, 'capture')
    assert hasattr(config, 'feature')
    assert hasattr(config, 'decision')
    assert hasattr(config, 'monitoring')
    assert hasattr(config, 'security')
    
    # Test configuration validation
    config.validate()


def test_logger_setup():
    """Test logger setup."""
    logger = get_logger(__name__)
    assert logger is not None
    assert logger.name == __name__


def test_feature_extraction():
    """Test basic feature extraction."""
    from src.fe.extract import FeatureExtractor
    
    # Initialize feature extractor
    extractor = FeatureExtractor()
    
    # Test feature processing
    sample_flow = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'src_port': 80,
        'dst_port': 8080,
        'protocol': 'TCP',
        'timestamp': 1234567890.0,
        'duration': 10.5,
        'packet_count': 100,
        'byte_count': 5000,
        'packets_per_second': 10.0,
        'bytes_per_second': 500.0,
        'avg_packet_size': 50.0,
        'std_packet_size': 5.0,
        'min_packet_size': 40,
        'max_packet_size': 60,
        'tcp_flags': {'SYN': 1, 'ACK': 1},
        'http_features': {},
        'dns_features': {},
        'time_of_day': 12.5,
        'day_of_week': 1,
        'entropy': 2.5,
        'unique_dst_ports': 5,
        'unique_dst_ips': 3,
        'recent_flows': 10,
        'recent_bytes': 1000,
        'recent_packets': 20
    }
    
    # Test feature processing
    feature_vector = extractor.feature_processor.process_features(sample_flow)
    
    assert feature_vector is not None
    assert len(feature_vector) > 0
    assert isinstance(feature_vector, np.ndarray)


def test_model_inference():
    """Test model inference."""
    from src.inference.model_server import ModelServer, FeatureProcessor
    
    # Initialize model server
    model_server = ModelServer()
    
    # Test feature processor
    processor = FeatureProcessor()
    
    sample_features = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'duration': 10.5,
        'packet_count': 100,
        'byte_count': 5000,
        'packets_per_second': 10.0,
        'bytes_per_second': 500.0,
        'avg_packet_size': 50.0,
        'std_packet_size': 5.0,
        'time_of_day': 12.5,
        'day_of_week': 1,
        'entropy': 2.5,
        'unique_dst_ports': 5,
        'unique_dst_ips': 3,
        'recent_flows': 10,
        'recent_bytes': 1000,
        'recent_packets': 20,
        'tcp_flags': {'SYN': 1, 'ACK': 1},
        'http_features': {},
        'dns_features': {}
    }
    
    # Test feature processing
    feature_vector = processor.process_features(sample_features)
    
    assert feature_vector is not None
    assert len(feature_vector) > 0
    assert isinstance(feature_vector, np.ndarray)


def test_decision_engine():
    """Test decision engine."""
    from src.decision.engine import DecisionEngine, Policy, PolicyEngine
    
    # Test policy engine
    policy_engine = PolicyEngine()
    
    # Test policy evaluation
    context = {
        'src_ip': '192.168.1.1',
        'dst_ip': '192.168.1.2',
        'prediction': 'attack',
        'severity': 'high',
        'risk_score': 0.9
    }
    
    decisions = policy_engine.evaluate_policies(context)
    
    assert isinstance(decisions, list)
    assert len(decisions) > 0  # Should have at least one decision for attack


def test_metrics_collection():
    """Test metrics collection."""
    from src.monitoring.metrics import MetricsCollector, PrometheusMetrics
    
    # Test Prometheus metrics
    prometheus = PrometheusMetrics(port=9091)  # Use different port for testing
    
    # Test metric recording
    prometheus.record_packet_processed('test_source', 'TCP')
    prometheus.record_feature_extracted('flow_features')
    prometheus.record_inference_completed('random_forest', 'attack')
    prometheus.record_anomaly_detected('high')
    prometheus.record_attack_classified('ddos', 'critical')
    prometheus.record_block_executed('high_risk_policy', 'attack_detected')
    prometheus.record_alert_generated('critical', 'high_risk_policy')
    prometheus.record_error('inference', 'model_error')
    prometheus.record_processing_latency('inference', 'prediction', 0.1)
    
    # Test gauge updates
    prometheus.set_active_connections(100)
    prometheus.set_blocked_ips(5)
    prometheus.set_model_accuracy('random_forest', 0.95)
    
    assert True  # If we get here, metrics recording worked


if __name__ == "__main__":
    pytest.main([__file__])
