"""
Monitoring and metrics collection for the AI-powered IDS/IPS system.
Provides real-time metrics, performance monitoring, and alerting.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import psutil
import numpy as np
from prometheus_client import Counter, Histogram, Gauge, start_http_server, CollectorRegistry
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point."""
    timestamp: float
    name: str
    value: Union[int, float]
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System performance metrics."""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    load_average: List[float]
    timestamp: float = field(default_factory=time.time)


@dataclass
class ApplicationMetrics:
    """Application-specific metrics."""
    packets_processed: int
    features_extracted: int
    inferences_completed: int
    decisions_made: int
    blocks_executed: int
    alerts_generated: int
    errors_occurred: int
    processing_latency_ms: float
    throughput_per_second: float
    timestamp: float = field(default_factory=time.time)


class PrometheusMetrics:
    """Prometheus metrics collector."""
    
    def __init__(self, port: int = 9090):
        self.port = port
        self.registry = CollectorRegistry()
        
        # Define metrics
        self.packets_processed = Counter(
            'ids_packets_processed_total',
            'Total number of packets processed',
            ['source', 'protocol'],
            registry=self.registry
        )
        
        self.features_extracted = Counter(
            'ids_features_extracted_total',
            'Total number of features extracted',
            ['feature_type'],
            registry=self.registry
        )
        
        self.inferences_completed = Counter(
            'ids_inferences_completed_total',
            'Total number of ML inferences completed',
            ['model_name', 'prediction'],
            registry=self.registry
        )
        
        self.anomalies_detected = Counter(
            'ids_anomalies_detected_total',
            'Total number of anomalies detected',
            ['severity'],
            registry=self.registry
        )
        
        self.attacks_classified = Counter(
            'ids_attacks_classified_total',
            'Total number of attacks classified',
            ['attack_type', 'severity'],
            registry=self.registry
        )
        
        self.blocks_executed = Counter(
            'ids_blocks_executed_total',
            'Total number of IP blocks executed',
            ['policy_name', 'reason'],
            registry=self.registry
        )
        
        self.alerts_generated = Counter(
            'ids_alerts_generated_total',
            'Total number of alerts generated',
            ['severity', 'policy_name'],
            registry=self.registry
        )
        
        self.errors_occurred = Counter(
            'ids_errors_total',
            'Total number of errors',
            ['component', 'error_type'],
            registry=self.registry
        )
        
        self.processing_latency = Histogram(
            'ids_processing_latency_seconds',
            'Processing latency in seconds',
            ['component', 'operation'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
            registry=self.registry
        )
        
        self.active_connections = Gauge(
            'ids_active_connections',
            'Number of active network connections',
            registry=self.registry
        )
        
        self.blocked_ips = Gauge(
            'ids_blocked_ips',
            'Number of currently blocked IP addresses',
            registry=self.registry
        )
        
        self.model_accuracy = Gauge(
            'ids_model_accuracy',
            'Model accuracy percentage',
            ['model_name'],
            registry=self.registry
        )
        
        self.system_cpu = Gauge(
            'ids_system_cpu_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory = Gauge(
            'ids_system_memory_percent',
            'System memory usage percentage',
            registry=self.registry
        )
        
        self.system_load = Gauge(
            'ids_system_load_average',
            'System load average',
            ['period'],
            registry=self.registry
        )
    
    def start_server(self):
        """Start Prometheus metrics server."""
        try:
            start_http_server(self.port, registry=self.registry)
            logger.info(f"Prometheus metrics server started on port {self.port}")
        except Exception as e:
            logger.error(f"Failed to start Prometheus metrics server: {e}")
    
    def record_packet_processed(self, source: str, protocol: str):
        """Record a processed packet."""
        self.packets_processed.labels(source=source, protocol=protocol).inc()
    
    def record_feature_extracted(self, feature_type: str):
        """Record a feature extraction."""
        self.features_extracted.labels(feature_type=feature_type).inc()
    
    def record_inference_completed(self, model_name: str, prediction: str):
        """Record a completed inference."""
        self.inferences_completed.labels(model_name=model_name, prediction=prediction).inc()
    
    def record_anomaly_detected(self, severity: str):
        """Record an anomaly detection."""
        self.anomalies_detected.labels(severity=severity).inc()
    
    def record_attack_classified(self, attack_type: str, severity: str):
        """Record an attack classification."""
        self.attacks_classified.labels(attack_type=attack_type, severity=severity).inc()
    
    def record_block_executed(self, policy_name: str, reason: str):
        """Record an IP block execution."""
        self.blocks_executed.labels(policy_name=policy_name, reason=reason).inc()
    
    def record_alert_generated(self, severity: str, policy_name: str):
        """Record an alert generation."""
        self.alerts_generated.labels(severity=severity, policy_name=policy_name).inc()
    
    def record_error(self, component: str, error_type: str):
        """Record an error occurrence."""
        self.errors_occurred.labels(component=component, error_type=error_type).inc()
    
    def record_processing_latency(self, component: str, operation: str, latency: float):
        """Record processing latency."""
        self.processing_latency.labels(component=component, operation=operation).observe(latency)
    
    def set_active_connections(self, count: int):
        """Set active connections count."""
        self.active_connections.set(count)
    
    def set_blocked_ips(self, count: int):
        """Set blocked IPs count."""
        self.blocked_ips.set(count)
    
    def set_model_accuracy(self, model_name: str, accuracy: float):
        """Set model accuracy."""
        self.model_accuracy.labels(model_name=model_name).set(accuracy)
    
    def update_system_metrics(self, metrics: SystemMetrics):
        """Update system metrics."""
        self.system_cpu.set(metrics.cpu_percent)
        self.system_memory.set(metrics.memory_percent)
        self.system_load.labels(period='1m').set(metrics.load_average[0])
        self.system_load.labels(period='5m').set(metrics.load_average[1])
        self.system_load.labels(period='15m').set(metrics.load_average[2])


class MetricsCollector:
    """Main metrics collection service."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.prometheus_metrics = PrometheusMetrics(self.config.monitoring.metrics_port)
        
        # Kafka components
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        
        # Metrics storage
        self.metrics_buffer: deque = deque(maxlen=10000)
        self.system_metrics_history: deque = deque(maxlen=1000)
        self.application_metrics_history: deque = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'metrics_collected': 0,
            'alerts_sent': 0,
            'errors': 0,
            'start_time': None
        }
        
        self.running = False
    
    async def start(self):
        """Start the metrics collection service."""
        try:
            logger.info("Starting metrics collection service...")
            
            # Start Prometheus server
            self.prometheus_metrics.start_server()
            
            # Initialize Kafka consumer
            self.kafka_consumer = KafkaConsumer(
                'metrics-events',
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                group_id=f"{self.config.kafka.consumer_group}_metrics",
                auto_offset_reset=self.config.kafka.auto_offset_reset,
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            
            # Initialize Kafka producer
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Start collection tasks
            asyncio.create_task(self._collect_system_metrics())
            asyncio.create_task(self._process_metrics_events())
            asyncio.create_task(self._send_metrics_to_kafka())
            
            logger.info("Metrics collection service started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start metrics collection service: {e}")
            raise
    
    async def stop(self):
        """Stop the metrics collection service."""
        try:
            self.running = False
            
            if self.kafka_consumer:
                self.kafka_consumer.close()
            
            if self.kafka_producer:
                self.kafka_producer.close()
            
            logger.info("Metrics collection service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping metrics collection service: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics."""
        while self.running:
            try:
                # Collect system metrics
                system_metrics = self._get_system_metrics()
                self.system_metrics_history.append(system_metrics)
                
                # Update Prometheus metrics
                self.prometheus_metrics.update_system_metrics(system_metrics)
                
                # Check for alerts
                await self._check_system_alerts(system_metrics)
                
                await asyncio.sleep(10)  # Collect every 10 seconds
            
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(10)
    
    def _get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_mb = memory.used / (1024 * 1024)
            memory_total_mb = memory.total / (1024 * 1024)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage_percent = disk.percent
            
            # Network usage
            network = psutil.net_io_counters()
            network_bytes_sent = network.bytes_sent
            network_bytes_recv = network.bytes_recv
            
            # Load average
            load_average = psutil.getloadavg()
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_used_mb=memory_used_mb,
                memory_total_mb=memory_total_mb,
                disk_usage_percent=disk_usage_percent,
                network_bytes_sent=network_bytes_sent,
                network_bytes_recv=network_bytes_recv,
                load_average=list(load_average)
            )
        
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                memory_total_mb=0.0,
                disk_usage_percent=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                load_average=[0.0, 0.0, 0.0]
            )
    
    async def _check_system_alerts(self, metrics: SystemMetrics):
        """Check for system alert conditions."""
        try:
            alerts = []
            
            # High CPU usage
            if metrics.cpu_percent > 80:
                alerts.append({
                    'type': 'high_cpu',
                    'severity': 'warning' if metrics.cpu_percent < 90 else 'critical',
                    'value': metrics.cpu_percent,
                    'threshold': 80
                })
            
            # High memory usage
            if metrics.memory_percent > 85:
                alerts.append({
                    'type': 'high_memory',
                    'severity': 'warning' if metrics.memory_percent < 95 else 'critical',
                    'value': metrics.memory_percent,
                    'threshold': 85
                })
            
            # High disk usage
            if metrics.disk_usage_percent > 90:
                alerts.append({
                    'type': 'high_disk',
                    'severity': 'warning' if metrics.disk_usage_percent < 95 else 'critical',
                    'value': metrics.disk_usage_percent,
                    'threshold': 90
                })
            
            # High load average
            if metrics.load_average[0] > 4.0:
                alerts.append({
                    'type': 'high_load',
                    'severity': 'warning' if metrics.load_average[0] < 8.0 else 'critical',
                    'value': metrics.load_average[0],
                    'threshold': 4.0
                })
            
            # Send alerts
            for alert in alerts:
                await self._send_alert(alert)
        
        except Exception as e:
            logger.error(f"Error checking system alerts: {e}")
    
    async def _process_metrics_events(self):
        """Process metrics events from Kafka."""
        while self.running:
            try:
                # Poll for messages
                message_batch = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            event = message.value
                            await self._process_metrics_event(event)
                            self.stats['metrics_collected'] += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing metrics event: {e}")
                            self.stats['errors'] += 1
                
            except Exception as e:
                logger.error(f"Error in metrics event processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_metrics_event(self, event: Dict[str, Any]):
        """Process a single metrics event."""
        try:
            event_type = event.get('type', 'unknown')
            
            if event_type == 'packet_processed':
                self.prometheus_metrics.record_packet_processed(
                    event.get('source', 'unknown'),
                    event.get('protocol', 'unknown')
                )
            
            elif event_type == 'feature_extracted':
                self.prometheus_metrics.record_feature_extracted(
                    event.get('feature_type', 'unknown')
                )
            
            elif event_type == 'inference_completed':
                self.prometheus_metrics.record_inference_completed(
                    event.get('model_name', 'unknown'),
                    event.get('prediction', 'unknown')
                )
            
            elif event_type == 'anomaly_detected':
                self.prometheus_metrics.record_anomaly_detected(
                    event.get('severity', 'low')
                )
            
            elif event_type == 'attack_classified':
                self.prometheus_metrics.record_attack_classified(
                    event.get('attack_type', 'unknown'),
                    event.get('severity', 'low')
                )
            
            elif event_type == 'block_executed':
                self.prometheus_metrics.record_block_executed(
                    event.get('policy_name', 'unknown'),
                    event.get('reason', 'unknown')
                )
            
            elif event_type == 'alert_generated':
                self.prometheus_metrics.record_alert_generated(
                    event.get('severity', 'low'),
                    event.get('policy_name', 'unknown')
                )
            
            elif event_type == 'error_occurred':
                self.prometheus_metrics.record_error(
                    event.get('component', 'unknown'),
                    event.get('error_type', 'unknown')
                )
            
            elif event_type == 'processing_latency':
                self.prometheus_metrics.record_processing_latency(
                    event.get('component', 'unknown'),
                    event.get('operation', 'unknown'),
                    event.get('latency', 0.0)
                )
            
            # Store in buffer
            self.metrics_buffer.append(event)
        
        except Exception as e:
            logger.error(f"Error processing metrics event: {e}")
            self.stats['errors'] += 1
    
    async def _send_metrics_to_kafka(self):
        """Send aggregated metrics to Kafka."""
        while self.running:
            try:
                if self.metrics_buffer:
                    # Get recent metrics
                    recent_metrics = list(self.metrics_buffer)[-100:]  # Last 100 metrics
                    
                    # Calculate aggregated metrics
                    aggregated = self._calculate_aggregated_metrics(recent_metrics)
                    
                    # Send to Kafka
                    if self.kafka_producer:
                        future = self.kafka_producer.send(
                            'aggregated-metrics',
                            key='metrics',
                            value=aggregated
                        )
                        
                        try:
                            future.get(timeout=1)
                        except KafkaError as e:
                            logger.error(f"Failed to send metrics to Kafka: {e}")
                
                await asyncio.sleep(30)  # Send every 30 seconds
            
            except Exception as e:
                logger.error(f"Error sending metrics to Kafka: {e}")
                await asyncio.sleep(30)
    
    def _calculate_aggregated_metrics(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate aggregated metrics from recent data."""
        try:
            current_time = time.time()
            
            # Count events by type
            event_counts = defaultdict(int)
            for metric in metrics:
                event_counts[metric.get('type', 'unknown')] += 1
            
            # Calculate rates
            time_window = 60  # 1 minute window
            recent_metrics = [m for m in metrics if m.get('timestamp', 0) > current_time - time_window]
            
            rates = {}
            for event_type in event_counts:
                count = len([m for m in recent_metrics if m.get('type') == event_type])
                rates[f"{event_type}_per_minute"] = count
            
            return {
                'timestamp': current_time,
                'event_counts': dict(event_counts),
                'rates': rates,
                'total_events': len(metrics),
                'time_window_seconds': time_window
            }
        
        except Exception as e:
            logger.error(f"Error calculating aggregated metrics: {e}")
            return {'timestamp': time.time(), 'error': str(e)}
    
    async def _send_alert(self, alert: Dict[str, Any]):
        """Send alert notification."""
        try:
            alert_data = {
                'timestamp': time.time(),
                'type': alert['type'],
                'severity': alert['severity'],
                'value': alert['value'],
                'threshold': alert['threshold'],
                'message': f"System alert: {alert['type']} is {alert['value']} (threshold: {alert['threshold']})"
            }
            
            if self.kafka_producer:
                future = self.kafka_producer.send(
                    'system-alerts',
                    key='system',
                    value=alert_data
                )
                
                try:
                    future.get(timeout=1)
                    self.stats['alerts_sent'] += 1
                except KafkaError as e:
                    logger.error(f"Failed to send alert to Kafka: {e}")
        
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def record_metric(self, name: str, value: Union[int, float], labels: Dict[str, str] = None):
        """Record a custom metric."""
        try:
            metric = MetricPoint(
                timestamp=time.time(),
                name=name,
                value=value,
                labels=labels or {}
            )
            
            self.metrics_buffer.append({
                'type': 'custom_metric',
                'name': name,
                'value': value,
                'labels': labels or {},
                'timestamp': metric.timestamp
            })
        
        except Exception as e:
            logger.error(f"Error recording metric: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get metrics collection statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'metrics_collected': self.stats['metrics_collected'],
            'alerts_sent': self.stats['alerts_sent'],
            'errors': self.stats['errors'],
            'metrics_per_second': self.stats['metrics_collected'] / uptime if uptime > 0 else 0,
            'buffer_size': len(self.metrics_buffer),
            'system_metrics_count': len(self.system_metrics_history),
            'application_metrics_count': len(self.application_metrics_history)
        }
    
    def get_system_metrics(self) -> List[SystemMetrics]:
        """Get recent system metrics."""
        return list(self.system_metrics_history)
    
    def get_application_metrics(self) -> List[ApplicationMetrics]:
        """Get recent application metrics."""
        return list(self.application_metrics_history)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        try:
            current_time = time.time()
            recent_metrics = [m for m in self.metrics_buffer if m.get('timestamp', 0) > current_time - 300]  # Last 5 minutes
            
            # Calculate summary statistics
            event_types = defaultdict(int)
            for metric in recent_metrics:
                event_types[metric.get('type', 'unknown')] += 1
            
            # Get latest system metrics
            latest_system = self.system_metrics_history[-1] if self.system_metrics_history else None
            
            return {
                'timestamp': current_time,
                'recent_events': dict(event_types),
                'total_events': len(recent_metrics),
                'system_metrics': {
                    'cpu_percent': latest_system.cpu_percent if latest_system else 0,
                    'memory_percent': latest_system.memory_percent if latest_system else 0,
                    'disk_usage_percent': latest_system.disk_usage_percent if latest_system else 0,
                    'load_average': latest_system.load_average if latest_system else [0, 0, 0]
                },
                'collection_stats': self.get_stats()
            }
        
        except Exception as e:
            logger.error(f"Error getting metrics summary: {e}")
            return {'error': str(e)}
