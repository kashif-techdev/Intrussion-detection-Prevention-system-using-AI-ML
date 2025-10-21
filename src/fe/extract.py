"""
Real-time feature extraction for the AI-powered IDS/IPS system.
Extracts statistical, temporal, and protocol-specific features from network flows.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FlowFeatures:
    """Flow-level features extracted from network data."""
    # Basic flow information
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float
    
    # Flow statistics
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    
    # Packet size statistics
    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    
    # Protocol-specific features
    tcp_flags: Dict[str, int] = field(default_factory=dict)
    http_features: Dict[str, Any] = field(default_factory=dict)
    dns_features: Dict[str, Any] = field(default_factory=dict)
    
    # Temporal features
    time_of_day: float = 0.0
    day_of_week: int = 0
    
    # Anomaly indicators
    entropy: float = 0.0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    
    # Aggregated features (sliding windows)
    recent_flows: int = 0
    recent_bytes: int = 0
    recent_packets: int = 0


class FeatureExtractor:
    """Real-time feature extraction service."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.window_size = self.config.feature.window_size
        self.batch_size = self.config.feature.batch_size
        
        # Data structures for feature computation
        self.flow_buffer: Dict[str, List[Dict]] = defaultdict(list)
        self.host_stats: Dict[str, Dict] = defaultdict(lambda: {
            'flows': deque(maxlen=1000),
            'bytes': deque(maxlen=1000),
            'packets': deque(maxlen=1000),
            'unique_dst_ports': set(),
            'unique_dst_ips': set()
        })
        
        # Kafka components
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        
        # Statistics
        self.stats = {
            'flows_processed': 0,
            'features_extracted': 0,
            'errors': 0,
            'start_time': None
        }
        
        self.running = False
    
    async def start(self):
        """Start the feature extraction service."""
        try:
            logger.info("Starting feature extraction service...")
            
            # Initialize Kafka consumer
            self.kafka_consumer = KafkaConsumer(
                self.config.kafka.topics['network_logs'],
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                group_id=self.config.kafka.consumer_group,
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
            
            # Start processing loop
            asyncio.create_task(self._process_flows())
            
            logger.info("Feature extraction service started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start feature extraction service: {e}")
            raise
    
    async def stop(self):
        """Stop the feature extraction service."""
        try:
            self.running = False
            
            if self.kafka_consumer:
                self.kafka_consumer.close()
            
            if self.kafka_producer:
                self.kafka_producer.close()
            
            logger.info("Feature extraction service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping feature extraction service: {e}")
    
    async def _process_flows(self):
        """Main processing loop for network flows."""
        while self.running:
            try:
                # Poll for messages
                message_batch = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            flow_data = message.value
                            await self._extract_features(flow_data)
                            self.stats['flows_processed'] += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing flow: {e}")
                            self.stats['errors'] += 1
                
                # Process buffered flows periodically
                await self._process_buffered_flows()
                
            except Exception as e:
                logger.error(f"Error in flow processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _extract_features(self, flow_data: Dict[str, Any]):
        """Extract features from a single flow."""
        try:
            # Create flow key
            flow_key = f"{flow_data.get('src_ip', '')}:{flow_data.get('src_port', 0)}-{flow_data.get('dst_ip', '')}:{flow_data.get('dst_port', 0)}"
            
            # Add to buffer
            self.flow_buffer[flow_key].append(flow_data)
            
            # Update host statistics
            src_ip = flow_data.get('src_ip', '')
            if src_ip:
                self._update_host_stats(src_ip, flow_data)
            
            # Extract features if buffer is full
            if len(self.flow_buffer[flow_key]) >= self.batch_size:
                features = await self._compute_flow_features(flow_key)
                if features:
                    await self._send_features(features)
                    self.stats['features_extracted'] += 1
                
                # Clear buffer
                del self.flow_buffer[flow_key]
        
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            self.stats['errors'] += 1
    
    def _update_host_stats(self, src_ip: str, flow_data: Dict[str, Any]):
        """Update host-level statistics."""
        host_stats = self.host_stats[src_ip]
        current_time = time.time()
        
        # Add to recent flows
        host_stats['flows'].append({
            'timestamp': current_time,
            'bytes': flow_data.get('orig_bytes', 0) + flow_data.get('resp_bytes', 0),
            'packets': flow_data.get('orig_pkts', 0) + flow_data.get('resp_pkts', 0)
        })
        
        # Update unique destinations
        dst_ip = flow_data.get('dst_ip', '')
        dst_port = flow_data.get('dst_port', 0)
        
        if dst_ip:
            host_stats['unique_dst_ips'].add(dst_ip)
        if dst_port:
            host_stats['unique_dst_ports'].add(dst_port)
    
    async def _compute_flow_features(self, flow_key: str) -> Optional[FlowFeatures]:
        """Compute comprehensive features for a flow."""
        try:
            flows = self.flow_buffer[flow_key]
            if not flows:
                return None
            
            # Sort by timestamp
            flows.sort(key=lambda x: x.get('timestamp', 0))
            
            # Basic flow information
            first_flow = flows[0]
            last_flow = flows[-1]
            
            src_ip = first_flow.get('src_ip', '')
            dst_ip = first_flow.get('dst_ip', '')
            src_port = first_flow.get('src_port', 0)
            dst_port = first_flow.get('dst_port', 0)
            protocol = first_flow.get('protocol', '')
            timestamp = first_flow.get('timestamp', time.time())
            
            # Flow statistics
            duration = last_flow.get('timestamp', timestamp) - timestamp
            total_bytes = sum(f.get('orig_bytes', 0) + f.get('resp_bytes', 0) for f in flows)
            total_packets = sum(f.get('orig_pkts', 0) + f.get('resp_pkts', 0) for f in flows)
            
            # Packet size statistics
            packet_sizes = []
            for flow in flows:
                if 'orig_bytes' in flow and 'orig_pkts' in flow and flow['orig_pkts'] > 0:
                    packet_sizes.append(flow['orig_bytes'] / flow['orig_pkts'])
                if 'resp_bytes' in flow and 'resp_pkts' in flow and flow['resp_pkts'] > 0:
                    packet_sizes.append(flow['resp_bytes'] / flow['resp_pkts'])
            
            avg_packet_size = np.mean(packet_sizes) if packet_sizes else 0
            std_packet_size = np.std(packet_sizes) if packet_sizes else 0
            min_packet_size = min(packet_sizes) if packet_sizes else 0
            max_packet_size = max(packet_sizes) if packet_sizes else 0
            
            # Protocol-specific features
            tcp_flags = self._extract_tcp_flags(flows)
            http_features = self._extract_http_features(flows)
            dns_features = self._extract_dns_features(flows)
            
            # Temporal features
            dt = pd.to_datetime(timestamp, unit='s')
            time_of_day = dt.hour + dt.minute / 60.0
            day_of_week = dt.dayofweek
            
            # Anomaly indicators
            entropy = self._calculate_entropy(flows)
            
            # Host-level aggregated features
            host_stats = self.host_stats.get(src_ip, {})
            recent_flows = len([f for f in host_stats.get('flows', []) 
                              if f['timestamp'] > timestamp - self.window_size])
            recent_bytes = sum(f['bytes'] for f in host_stats.get('flows', []) 
                             if f['timestamp'] > timestamp - self.window_size)
            recent_packets = sum(f['packets'] for f in host_stats.get('flows', []) 
                               if f['timestamp'] > timestamp - self.window_size)
            
            # Create feature object
            features = FlowFeatures(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                timestamp=timestamp,
                duration=duration,
                packet_count=total_packets,
                byte_count=total_bytes,
                packets_per_second=total_packets / duration if duration > 0 else 0,
                bytes_per_second=total_bytes / duration if duration > 0 else 0,
                avg_packet_size=avg_packet_size,
                std_packet_size=std_packet_size,
                min_packet_size=min_packet_size,
                max_packet_size=max_packet_size,
                tcp_flags=tcp_flags,
                http_features=http_features,
                dns_features=dns_features,
                time_of_day=time_of_day,
                day_of_week=day_of_week,
                entropy=entropy,
                unique_dst_ports=len(host_stats.get('unique_dst_ports', set())),
                unique_dst_ips=len(host_stats.get('unique_dst_ips', set())),
                recent_flows=recent_flows,
                recent_bytes=recent_bytes,
                recent_packets=recent_packets
            )
            
            return features
        
        except Exception as e:
            logger.error(f"Error computing flow features: {e}")
            return None
    
    def _extract_tcp_flags(self, flows: List[Dict]) -> Dict[str, int]:
        """Extract TCP flag statistics."""
        flags = defaultdict(int)
        
        for flow in flows:
            if 'history' in flow:
                history = flow['history']
                flags['SYN'] += history.count('S')
                flags['ACK'] += history.count('A')
                flags['FIN'] += history.count('F')
                flags['RST'] += history.count('R')
                flags['PSH'] += history.count('P')
                flags['URG'] += history.count('U')
        
        return dict(flags)
    
    def _extract_http_features(self, flows: List[Dict]) -> Dict[str, Any]:
        """Extract HTTP-specific features."""
        features = {
            'request_count': 0,
            'response_count': 0,
            'status_codes': defaultdict(int),
            'uri_lengths': [],
            'user_agents': set(),
            'methods': defaultdict(int)
        }
        
        for flow in flows:
            # This would be populated from HTTP logs in a real implementation
            # For now, return empty features
            pass
        
        return {
            'request_count': features['request_count'],
            'response_count': features['response_count'],
            'status_codes': dict(features['status_codes']),
            'avg_uri_length': np.mean(features['uri_lengths']) if features['uri_lengths'] else 0,
            'unique_user_agents': len(features['user_agents']),
            'methods': dict(features['methods'])
        }
    
    def _extract_dns_features(self, flows: List[Dict]) -> Dict[str, Any]:
        """Extract DNS-specific features."""
        features = {
            'query_count': 0,
            'response_count': 0,
            'nxdomain_count': 0,
            'query_types': defaultdict(int),
            'domain_lengths': [],
            'unique_domains': set()
        }
        
        for flow in flows:
            # This would be populated from DNS logs in a real implementation
            # For now, return empty features
            pass
        
        return {
            'query_count': features['query_count'],
            'response_count': features['response_count'],
            'nxdomain_ratio': features['nxdomain_count'] / max(features['query_count'], 1),
            'query_types': dict(features['query_types']),
            'avg_domain_length': np.mean(features['domain_lengths']) if features['domain_lengths'] else 0,
            'unique_domains': len(features['unique_domains'])
        }
    
    def _calculate_entropy(self, flows: List[Dict]) -> float:
        """Calculate entropy of flow data."""
        try:
            # Combine all text data from flows
            text_data = []
            for flow in flows:
                for key, value in flow.items():
                    if isinstance(value, str):
                        text_data.append(value)
            
            if not text_data:
                return 0.0
            
            # Calculate character frequency
            text = ''.join(text_data)
            char_counts = defaultdict(int)
            for char in text:
                char_counts[char] += 1
            
            # Calculate entropy
            total_chars = len(text)
            entropy = 0.0
            for count in char_counts.values():
                if count > 0:
                    p = count / total_chars
                    entropy -= p * np.log2(p)
            
            return entropy
        
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    async def _send_features(self, features: FlowFeatures):
        """Send extracted features to Kafka."""
        try:
            # Convert features to dictionary
            features_dict = {
                'timestamp': features.timestamp,
                'src_ip': features.src_ip,
                'dst_ip': features.dst_ip,
                'src_port': features.src_port,
                'dst_port': features.dst_port,
                'protocol': features.protocol,
                'duration': features.duration,
                'packet_count': features.packet_count,
                'byte_count': features.byte_count,
                'packets_per_second': features.packets_per_second,
                'bytes_per_second': features.bytes_per_second,
                'avg_packet_size': features.avg_packet_size,
                'std_packet_size': features.std_packet_size,
                'min_packet_size': features.min_packet_size,
                'max_packet_size': features.max_packet_size,
                'tcp_flags': features.tcp_flags,
                'http_features': features.http_features,
                'dns_features': features.dns_features,
                'time_of_day': features.time_of_day,
                'day_of_week': features.day_of_week,
                'entropy': features.entropy,
                'unique_dst_ports': features.unique_dst_ports,
                'unique_dst_ips': features.unique_dst_ips,
                'recent_flows': features.recent_flows,
                'recent_bytes': features.recent_bytes,
                'recent_packets': features.recent_packets
            }
            
            # Send to Kafka
            if self.kafka_producer:
                future = self.kafka_producer.send(
                    self.config.kafka.topics['features'],
                    key=features.src_ip,
                    value=features_dict
                )
                
                try:
                    future.get(timeout=1)
                except KafkaError as e:
                    logger.error(f"Failed to send features to Kafka: {e}")
                    self.stats['errors'] += 1
        
        except Exception as e:
            logger.error(f"Error sending features: {e}")
            self.stats['errors'] += 1
    
    async def _process_buffered_flows(self):
        """Process flows that have been buffered for too long."""
        current_time = time.time()
        
        for flow_key, flows in list(self.flow_buffer.items()):
            if flows and current_time - flows[0].get('timestamp', current_time) > self.window_size:
                features = await self._compute_flow_features(flow_key)
                if features:
                    await self._send_features(features)
                    self.stats['features_extracted'] += 1
                
                del self.flow_buffer[flow_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feature extraction statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'flows_processed': self.stats['flows_processed'],
            'features_extracted': self.stats['features_extracted'],
            'errors': self.stats['errors'],
            'flows_per_second': self.stats['flows_processed'] / uptime if uptime > 0 else 0,
            'features_per_second': self.stats['features_extracted'] / uptime if uptime > 0 else 0,
            'buffer_size': sum(len(flows) for flows in self.flow_buffer.values()),
            'host_stats_count': len(self.host_stats)
        }
