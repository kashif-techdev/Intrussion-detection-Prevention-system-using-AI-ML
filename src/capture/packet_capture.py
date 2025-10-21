"""
Packet capture service for the AI-powered IDS/IPS system.
Supports multiple capture methods: Zeek, Suricata, and Scapy.
"""

import asyncio
import json
import logging
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime

import psutil
from kafka import KafkaProducer
from kafka.errors import KafkaError

from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PacketInfo:
    """Packet information structure."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    payload: Optional[bytes] = None
    flags: Optional[Dict[str, bool]] = None


class ZeekCapture:
    """Zeek-based packet capture and log parsing."""
    
    def __init__(self, interface: str, output_dir: str):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.process: Optional[subprocess.Popen] = None
        self.log_files = {
            'conn': self.output_dir / 'conn.log',
            'http': self.output_dir / 'http.log',
            'dns': self.output_dir / 'dns.log',
            'ssl': self.output_dir / 'ssl.log'
        }
    
    async def start(self):
        """Start Zeek capture process."""
        try:
            # Zeek command with interface and output directory
            cmd = [
                'zeek',
                '-i', self.interface,
                '-C',  # Don't capture packets, just analyze
                '-r', '-',  # Read from stdin (for real-time)
                'local'
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.output_dir)
            )
            
            logger.info(f"Zeek capture started on interface {self.interface}")
            
        except Exception as e:
            logger.error(f"Failed to start Zeek capture: {e}")
            raise
    
    async def stop(self):
        """Stop Zeek capture process."""
        if self.process:
            self.process.terminate()
            self.process.wait()
            logger.info("Zeek capture stopped")
    
    def parse_conn_log(self, log_file: Path) -> List[Dict[str, Any]]:
        """Parse Zeek connection log file."""
        connections = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) >= 20:
                        conn = {
                            'timestamp': float(fields[0]),
                            'uid': fields[1],
                            'src_ip': fields[2],
                            'src_port': int(fields[3]),
                            'dst_ip': fields[4],
                            'dst_port': int(fields[5]),
                            'protocol': fields[6],
                            'service': fields[7],
                            'duration': float(fields[8]) if fields[8] != '-' else 0,
                            'orig_bytes': int(fields[9]) if fields[9] != '-' else 0,
                            'resp_bytes': int(fields[10]) if fields[10] != '-' else 0,
                            'conn_state': fields[11],
                            'local_orig': fields[12] == 'T',
                            'local_resp': fields[13] == 'T',
                            'missed_bytes': int(fields[14]) if fields[14] != '-' else 0,
                            'history': fields[15],
                            'orig_pkts': int(fields[16]) if fields[16] != '-' else 0,
                            'orig_ip_bytes': int(fields[17]) if fields[17] != '-' else 0,
                            'resp_pkts': int(fields[18]) if fields[18] != '-' else 0,
                            'resp_ip_bytes': int(fields[19]) if fields[19] != '-' else 0
                        }
                        connections.append(conn)
        
        except Exception as e:
            logger.error(f"Error parsing Zeek conn.log: {e}")
        
        return connections


class SuricataCapture:
    """Suricata-based packet capture and rule-based detection."""
    
    def __init__(self, interface: str, output_dir: str, rules_file: Optional[str] = None):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = rules_file
        self.process: Optional[subprocess.Popen] = None
        self.alert_file = self.output_dir / 'fast.log'
        self.eve_file = self.output_dir / 'eve.json'
    
    async def start(self):
        """Start Suricata capture process."""
        try:
            # Create Suricata configuration
            config_file = self.output_dir / 'suricata.yaml'
            self._create_suricata_config(config_file)
            
            # Suricata command
            cmd = [
                'suricata',
                '-i', self.interface,
                '-c', str(config_file),
                '-l', str(self.output_dir)
            ]
            
            if self.rules_file:
                cmd.extend(['-S', self.rules_file])
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            logger.info(f"Suricata capture started on interface {self.interface}")
            
        except Exception as e:
            logger.error(f"Failed to start Suricata capture: {e}")
            raise
    
    async def stop(self):
        """Stop Suricata capture process."""
        if self.process:
            self.process.terminate()
            self.process.wait()
            logger.info("Suricata capture stopped")
    
    def _create_suricata_config(self, config_file: Path):
        """Create basic Suricata configuration file."""
        config_content = f"""
%YAML 1.1
---
# Suricata configuration for AI-IDS-IPS

default-log-dir: {self.output_dir}
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Network interface
af-packet:
  - interface: {self.interface}
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 2048

# Logging
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: {self.output_dir}/suricata.log
    - eve-log:
        enabled: yes
        filetype: regular
        filename: {self.eve_file}
        types:
          - alert
          - http
          - dns
          - tls
          - files
          - ssh
          - smtp
          - flow
          - netflow
          - stats
          - drop
          - metadata
"""
        
        with open(config_file, 'w') as f:
            f.write(config_content)
    
    def parse_eve_log(self, log_file: Path) -> List[Dict[str, Any]]:
        """Parse Suricata EVE JSON log file."""
        events = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logger.error(f"Error parsing Suricata EVE log: {e}")
        
        return events


class ScapyCapture:
    """Scapy-based packet capture for custom analysis."""
    
    def __init__(self, interface: str, filter_expr: str = ""):
        self.interface = interface
        self.filter_expr = filter_expr
        self.capture_thread: Optional[threading.Thread] = None
        self.running = False
        self.callbacks: List[Callable[[PacketInfo], None]] = []
    
    async def start(self):
        """Start Scapy packet capture."""
        try:
            from scapy.all import sniff, get_if_list
            
            # Verify interface exists
            if self.interface not in get_if_list():
                raise ValueError(f"Interface {self.interface} not found")
            
            self.running = True
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True
            )
            self.capture_thread.start()
            
            logger.info(f"Scapy capture started on interface {self.interface}")
            
        except ImportError:
            logger.error("Scapy not available. Install with: pip install scapy")
            raise
        except Exception as e:
            logger.error(f"Failed to start Scapy capture: {e}")
            raise
    
    async def stop(self):
        """Stop Scapy packet capture."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Scapy capture stopped")
    
    def _capture_loop(self):
        """Main capture loop for Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            
            def packet_handler(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self._parse_packet(packet)
                    if packet_info:
                        for callback in self.callbacks:
                            callback(packet_info)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
            
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=packet_handler,
                stop_filter=lambda x: not self.running
            )
        
        except Exception as e:
            logger.error(f"Error in Scapy capture loop: {e}")
    
    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse Scapy packet into PacketInfo structure."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            timestamp = packet.time
            
            # Extract basic IP information
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # Extract port information based on protocol
            src_port = 0
            dst_port = 0
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            # Extract flags for TCP
            flags = None
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                flags = {
                    'SYN': bool(tcp_layer.flags & 0x02),
                    'ACK': bool(tcp_layer.flags & 0x10),
                    'FIN': bool(tcp_layer.flags & 0x01),
                    'RST': bool(tcp_layer.flags & 0x04),
                    'PSH': bool(tcp_layer.flags & 0x08),
                    'URG': bool(tcp_layer.flags & 0x20)
                }
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                payload=bytes(packet.payload) if packet.payload else None,
                flags=flags
            )
        
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    def add_callback(self, callback: Callable[[PacketInfo], None]):
        """Add packet processing callback."""
        self.callbacks.append(callback)


class PacketCaptureService:
    """Main packet capture service that coordinates different capture methods."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.capture_method = self.config.capture.capture_method
        self.interface = self.config.capture.interface
        self.output_dir = self.config.capture.output_dir
        
        # Initialize capture backend
        self.capture_backend = None
        self.kafka_producer: Optional[KafkaProducer] = None
        self.running = False
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'errors': 0,
            'start_time': None
        }
    
    async def start(self):
        """Start the packet capture service."""
        try:
            logger.info(f"Starting packet capture service with method: {self.capture_method}")
            
            # Initialize Kafka producer
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            
            # Initialize capture backend based on method
            if self.capture_method == "zeek":
                self.capture_backend = ZeekCapture(self.interface, self.output_dir)
            elif self.capture_method == "suricata":
                self.capture_backend = SuricataCapture(self.interface, self.output_dir)
            elif self.capture_method == "scapy":
                self.capture_backend = ScapyCapture(self.interface)
                # Add callback for packet processing
                self.capture_backend.add_callback(self._process_packet)
            else:
                raise ValueError(f"Unsupported capture method: {self.capture_method}")
            
            # Start capture backend
            await self.capture_backend.start()
            
            # Start log monitoring for Zeek/Suricata
            if self.capture_method in ["zeek", "suricata"]:
                asyncio.create_task(self._monitor_logs())
            
            self.running = True
            self.stats['start_time'] = time.time()
            
            logger.info("Packet capture service started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start packet capture service: {e}")
            raise
    
    async def stop(self):
        """Stop the packet capture service."""
        try:
            self.running = False
            
            if self.capture_backend:
                await self.capture_backend.stop()
            
            if self.kafka_producer:
                self.kafka_producer.close()
            
            logger.info("Packet capture service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping packet capture service: {e}")
    
    def _process_packet(self, packet_info: PacketInfo):
        """Process captured packet and send to Kafka."""
        try:
            self.stats['packets_captured'] += 1
            
            # Convert packet to dictionary
            packet_data = {
                'timestamp': packet_info.timestamp,
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'src_port': packet_info.src_port,
                'dst_port': packet_info.dst_port,
                'protocol': packet_info.protocol,
                'packet_size': packet_info.packet_size,
                'flags': packet_info.flags
            }
            
            # Send to Kafka
            if self.kafka_producer:
                future = self.kafka_producer.send(
                    self.config.kafka.topics['network_logs'],
                    key=packet_info.src_ip,
                    value=packet_data
                )
                
                # Handle send result
                try:
                    future.get(timeout=1)
                    self.stats['packets_processed'] += 1
                except KafkaError as e:
                    logger.error(f"Failed to send packet to Kafka: {e}")
                    self.stats['errors'] += 1
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self.stats['errors'] += 1
    
    async def _monitor_logs(self):
        """Monitor log files for Zeek/Suricata and process new entries."""
        while self.running:
            try:
                if self.capture_method == "zeek":
                    await self._process_zeek_logs()
                elif self.capture_method == "suricata":
                    await self._process_suricata_logs()
                
                await asyncio.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error monitoring logs: {e}")
                await asyncio.sleep(5)
    
    async def _process_zeek_logs(self):
        """Process Zeek log files."""
        try:
            if hasattr(self.capture_backend, 'parse_conn_log'):
                conn_file = self.capture_backend.log_files.get('conn')
                if conn_file and conn_file.exists():
                    connections = self.capture_backend.parse_conn_log(conn_file)
                    
                    for conn in connections:
                        # Send connection data to Kafka
                        if self.kafka_producer:
                            future = self.kafka_producer.send(
                                self.config.kafka.topics['network_logs'],
                                key=conn['src_ip'],
                                value=conn
                            )
                            try:
                                future.get(timeout=1)
                                self.stats['packets_processed'] += 1
                            except KafkaError as e:
                                logger.error(f"Failed to send connection to Kafka: {e}")
                                self.stats['errors'] += 1
        
        except Exception as e:
            logger.error(f"Error processing Zeek logs: {e}")
    
    async def _process_suricata_logs(self):
        """Process Suricata log files."""
        try:
            if hasattr(self.capture_backend, 'parse_eve_log'):
                eve_file = self.capture_backend.eve_file
                if eve_file and eve_file.exists():
                    events = self.capture_backend.parse_eve_log(eve_file)
                    
                    for event in events:
                        # Send event data to Kafka
                        if self.kafka_producer:
                            future = self.kafka_producer.send(
                                self.config.kafka.topics['network_logs'],
                                key=event.get('src_ip', 'unknown'),
                                value=event
                            )
                            try:
                                future.get(timeout=1)
                                self.stats['packets_processed'] += 1
                            except KafkaError as e:
                                logger.error(f"Failed to send event to Kafka: {e}")
                                self.stats['errors'] += 1
        
        except Exception as e:
            logger.error(f"Error processing Suricata logs: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture service statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'running': self.running,
            'capture_method': self.capture_method,
            'interface': self.interface,
            'uptime_seconds': uptime,
            'packets_captured': self.stats['packets_captured'],
            'packets_processed': self.stats['packets_processed'],
            'errors': self.stats['errors'],
            'packets_per_second': self.stats['packets_captured'] / uptime if uptime > 0 else 0
        }
