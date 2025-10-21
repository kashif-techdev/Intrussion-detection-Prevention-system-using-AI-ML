"""
Decision engine for the AI-powered IDS/IPS system.
Implements policy-based decision making and automated prevention actions.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
import subprocess
import ipaddress
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.utils.config import Config
from src.utils.logger import get_logger, security_logger

logger = get_logger(__name__)


@dataclass
class Policy:
    """Security policy definition."""
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: List[str]
    priority: int = 1
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class Decision:
    """Decision result from policy evaluation."""
    timestamp: float
    src_ip: str
    dst_ip: str
    policy_name: str
    action: str
    reason: str
    severity: str
    risk_score: float
    auto_block: bool = False
    block_duration: int = 300  # seconds
    requires_approval: bool = False


@dataclass
class BlockedIP:
    """Information about a blocked IP address."""
    ip: str
    reason: str
    blocked_at: datetime
    expires_at: datetime
    policy_name: str
    severity: str
    auto_unblock: bool = True


class PolicyEngine:
    """Policy engine for evaluating security policies."""
    
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.default_policies = self._create_default_policies()
        self._load_default_policies()
    
    def _create_default_policies(self) -> List[Policy]:
        """Create default security policies."""
        return [
            Policy(
                name="high_risk_attack",
                description="Block high-risk attacks immediately",
                conditions={
                    "prediction": "attack",
                    "severity": "high",
                    "risk_score": {"min": 0.8}
                },
                actions=["block_ip", "alert"],
                priority=1
            ),
            Policy(
                name="suspicious_activity",
                description="Alert on suspicious activity",
                conditions={
                    "prediction": "suspicious",
                    "severity": "medium",
                    "risk_score": {"min": 0.6}
                },
                actions=["alert", "monitor"],
                priority=2
            ),
            Policy(
                name="anomaly_detection",
                description="Alert on anomalies",
                conditions={
                    "is_anomaly": True,
                    "anomaly_score": {"min": 0.7}
                },
                actions=["alert"],
                priority=3
            ),
            Policy(
                name="whitelist_override",
                description="Allow whitelisted IPs",
                conditions={
                    "src_ip": {"in_whitelist": True}
                },
                actions=["allow"],
                priority=0
            ),
            Policy(
                name="blacklist_immediate",
                description="Immediately block blacklisted IPs",
                conditions={
                    "src_ip": {"in_blacklist": True}
                },
                actions=["block_ip", "alert"],
                priority=0
            )
        ]
    
    def _load_default_policies(self):
        """Load default policies into the engine."""
        for policy in self.default_policies:
            self.policies[policy.name] = policy
        logger.info(f"Loaded {len(self.default_policies)} default policies")
    
    def add_policy(self, policy: Policy):
        """Add a new policy to the engine."""
        policy.updated_at = datetime.now()
        self.policies[policy.name] = policy
        logger.info(f"Added policy: {policy.name}")
    
    def remove_policy(self, policy_name: str):
        """Remove a policy from the engine."""
        if policy_name in self.policies:
            del self.policies[policy_name]
            logger.info(f"Removed policy: {policy_name}")
    
    def update_policy(self, policy_name: str, updates: Dict[str, Any]):
        """Update an existing policy."""
        if policy_name in self.policies:
            policy = self.policies[policy_name]
            for key, value in updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
            policy.updated_at = datetime.now()
            logger.info(f"Updated policy: {policy_name}")
    
    def evaluate_policies(self, context: Dict[str, Any]) -> List[Decision]:
        """Evaluate all policies against the given context."""
        decisions = []
        
        # Sort policies by priority (lower number = higher priority)
        sorted_policies = sorted(self.policies.values(), key=lambda p: p.priority)
        
        for policy in sorted_policies:
            if not policy.enabled:
                continue
            
            if self._evaluate_conditions(policy.conditions, context):
                decision = self._create_decision(policy, context)
                decisions.append(decision)
                
                # If this is an allow decision, stop processing
                if "allow" in decision.action:
                    break
        
        return decisions
    
    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate policy conditions against context."""
        try:
            for field, expected in conditions.items():
                if field not in context:
                    return False
                
                actual = context[field]
                
                if isinstance(expected, dict):
                    if not self._evaluate_condition_dict(expected, actual):
                        return False
                elif isinstance(expected, list):
                    if actual not in expected:
                        return False
                else:
                    if actual != expected:
                        return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error evaluating conditions: {e}")
            return False
    
    def _evaluate_condition_dict(self, expected: Dict[str, Any], actual: Any) -> bool:
        """Evaluate dictionary-based conditions."""
        for operator, value in expected.items():
            if operator == "min":
                if actual < value:
                    return False
            elif operator == "max":
                if actual > value:
                    return False
            elif operator == "in_whitelist":
                # This would be checked against actual whitelist
                return False  # Placeholder
            elif operator == "in_blacklist":
                # This would be checked against actual blacklist
                return False  # Placeholder
            else:
                return False
        
        return True
    
    def _create_decision(self, policy: Policy, context: Dict[str, Any]) -> Decision:
        """Create a decision based on policy and context."""
        return Decision(
            timestamp=time.time(),
            src_ip=context.get('src_ip', 'unknown'),
            dst_ip=context.get('dst_ip', 'unknown'),
            policy_name=policy.name,
            action=','.join(policy.actions),
            reason=f"Policy {policy.name}: {policy.description}",
            severity=context.get('severity', 'low'),
            risk_score=context.get('risk_score', 0.0),
            auto_block="block_ip" in policy.actions,
            block_duration=300 if "block_ip" in policy.actions else 0,
            requires_approval=policy.priority > 1
        )


class PreventionEngine:
    """Engine for executing prevention actions."""
    
    def __init__(self, config: Config):
        self.config = config
        self.blocked_ips: Dict[str, BlockedIP] = {}
        self.whitelist: Set[str] = set(config.decision.whitelist_ips)
        self.blacklist: Set[str] = set(config.decision.blacklist_ips)
        
        # Initialize prevention methods
        self.prevention_methods = {
            'iptables': self._block_with_iptables,
            'nftables': self._block_with_nftables,
            'cloud_firewall': self._block_with_cloud_firewall
        }
    
    async def execute_decision(self, decision: Decision):
        """Execute a prevention decision."""
        try:
            logger.info(f"Executing decision: {decision.action} for {decision.src_ip}")
            
            # Check if IP is whitelisted
            if decision.src_ip in self.whitelist:
                logger.info(f"IP {decision.src_ip} is whitelisted, skipping action")
                return
            
            # Execute actions
            actions = decision.action.split(',')
            for action in actions:
                action = action.strip()
                
                if action == "block_ip":
                    await self._block_ip(decision)
                elif action == "alert":
                    await self._send_alert(decision)
                elif action == "monitor":
                    await self._monitor_ip(decision)
                elif action == "allow":
                    await self._allow_ip(decision)
            
            # Log security event
            security_logger.log_attack_detected(
                attack_type=decision.policy_name,
                source_ip=decision.src_ip,
                target_ip=decision.dst_ip,
                confidence=decision.risk_score,
                details={
                    'action': decision.action,
                    'severity': decision.severity,
                    'reason': decision.reason
                }
            )
        
        except Exception as e:
            logger.error(f"Error executing decision: {e}")
    
    async def _block_ip(self, decision: Decision):
        """Block an IP address."""
        try:
            ip = decision.src_ip
            
            # Check if already blocked
            if ip in self.blocked_ips:
                logger.info(f"IP {ip} is already blocked")
                return
            
            # Create blocked IP record
            blocked_ip = BlockedIP(
                ip=ip,
                reason=decision.reason,
                blocked_at=datetime.now(),
                expires_at=datetime.now() + timedelta(seconds=decision.block_duration),
                policy_name=decision.policy_name,
                severity=decision.severity,
                auto_unblock=decision.auto_block
            )
            
            # Add to blocked list
            self.blocked_ips[ip] = blocked_ip
            
            # Execute blocking action
            await self._execute_block(ip, decision)
            
            # Log blocking action
            security_logger.log_block_action(
                action="block",
                ip=ip,
                reason=decision.reason,
                duration=decision.block_duration
            )
            
            logger.info(f"Blocked IP {ip} for {decision.block_duration} seconds")
        
        except Exception as e:
            logger.error(f"Error blocking IP {decision.src_ip}: {e}")
    
    async def _execute_block(self, ip: str, decision: Decision):
        """Execute the actual blocking mechanism."""
        try:
            # Try iptables first (most common)
            if await self._block_with_iptables(ip):
                return
            
            # Try nftables as fallback
            if await self._block_with_nftables(ip):
                return
            
            # Log failure
            logger.error(f"Failed to block IP {ip} with any method")
        
        except Exception as e:
            logger.error(f"Error executing block for IP {ip}: {e}")
    
    async def _block_with_iptables(self, ip: str) -> bool:
        """Block IP using iptables."""
        try:
            # Check if iptables is available
            result = subprocess.run(['which', 'iptables'], capture_output=True)
            if result.returncode != 0:
                return False
            
            # Add blocking rule
            cmd = [
                'iptables', '-I', 'INPUT', '1',
                '-s', ip, '-j', 'DROP'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Blocked IP {ip} with iptables")
                return True
            else:
                logger.error(f"Failed to block IP {ip} with iptables: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip} with iptables: {e}")
            return False
    
    async def _block_with_nftables(self, ip: str) -> bool:
        """Block IP using nftables."""
        try:
            # Check if nftables is available
            result = subprocess.run(['which', 'nft'], capture_output=True)
            if result.returncode != 0:
                return False
            
            # Add blocking rule
            cmd = [
                'nft', 'add', 'rule', 'inet', 'filter', 'input',
                'ip', 'saddr', ip, 'drop'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Blocked IP {ip} with nftables")
                return True
            else:
                logger.error(f"Failed to block IP {ip} with nftables: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip} with nftables: {e}")
            return False
    
    async def _block_with_cloud_firewall(self, ip: str) -> bool:
        """Block IP using cloud firewall APIs."""
        try:
            # This would implement cloud-specific firewall APIs
            # AWS Security Groups, GCP Firewall, Azure NSG, etc.
            logger.info(f"Cloud firewall blocking for IP {ip} not implemented")
            return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip} with cloud firewall: {e}")
            return False
    
    async def _send_alert(self, decision: Decision):
        """Send alert notification."""
        try:
            alert_data = {
                'timestamp': decision.timestamp,
                'src_ip': decision.src_ip,
                'dst_ip': decision.dst_ip,
                'policy_name': decision.policy_name,
                'action': decision.action,
                'severity': decision.severity,
                'risk_score': decision.risk_score,
                'reason': decision.reason
            }
            
            # Send to Kafka for SIEM integration
            # This would be implemented with the Kafka producer
            
            logger.info(f"Alert sent for {decision.src_ip}: {decision.reason}")
        
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def _monitor_ip(self, decision: Decision):
        """Monitor IP for additional activity."""
        try:
            # Add to monitoring list
            # This would integrate with monitoring systems
            logger.info(f"Monitoring IP {decision.src_ip} for suspicious activity")
        
        except Exception as e:
            logger.error(f"Error monitoring IP {decision.src_ip}: {e}")
    
    async def _allow_ip(self, decision: Decision):
        """Allow IP (remove from any blocks)."""
        try:
            ip = decision.src_ip
            
            # Remove from blocked list if present
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                logger.info(f"Removed IP {ip} from blocked list")
            
            # Remove from iptables rules
            await self._unblock_with_iptables(ip)
            
            logger.info(f"Allowed IP {ip}")
        
        except Exception as e:
            logger.error(f"Error allowing IP {decision.src_ip}: {e}")
    
    async def _unblock_with_iptables(self, ip: str):
        """Remove IP block from iptables."""
        try:
            cmd = [
                'iptables', '-D', 'INPUT',
                '-s', ip, '-j', 'DROP'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Unblocked IP {ip} from iptables")
            else:
                logger.debug(f"IP {ip} was not blocked in iptables")
        
        except Exception as e:
            logger.error(f"Error unblocking IP {ip} from iptables: {e}")
    
    async def cleanup_expired_blocks(self):
        """Remove expired IP blocks."""
        try:
            current_time = datetime.now()
            expired_ips = []
            
            for ip, blocked_ip in self.blocked_ips.items():
                if blocked_ip.auto_unblock and blocked_ip.expires_at <= current_time:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                await self._unblock_with_iptables(ip)
                del self.blocked_ips[ip]
                logger.info(f"Auto-unblocked expired IP {ip}")
        
        except Exception as e:
            logger.error(f"Error cleaning up expired blocks: {e}")
    
    def get_blocked_ips(self) -> Dict[str, BlockedIP]:
        """Get list of currently blocked IPs."""
        return self.blocked_ips.copy()
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self.blocked_ips


class DecisionEngine:
    """Main decision engine service."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.policy_engine = PolicyEngine()
        self.prevention_engine = PreventionEngine(self.config)
        
        # Kafka components
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        
        # Statistics
        self.stats = {
            'decisions_processed': 0,
            'blocks_executed': 0,
            'alerts_sent': 0,
            'errors': 0,
            'start_time': None
        }
        
        self.running = False
    
    async def start(self):
        """Start the decision engine service."""
        try:
            logger.info("Starting decision engine service...")
            
            # Initialize Kafka consumer
            self.kafka_consumer = KafkaConsumer(
                self.config.kafka.topics['decisions'],
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                group_id=f"{self.config.kafka.consumer_group}_decision",
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
            asyncio.create_task(self._process_decisions())
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_task())
            
            logger.info("Decision engine service started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start decision engine service: {e}")
            raise
    
    async def stop(self):
        """Stop the decision engine service."""
        try:
            self.running = False
            
            if self.kafka_consumer:
                self.kafka_consumer.close()
            
            if self.kafka_producer:
                self.kafka_producer.close()
            
            logger.info("Decision engine service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping decision engine service: {e}")
    
    async def _process_decisions(self):
        """Main processing loop for inference results."""
        while self.running:
            try:
                # Poll for messages
                message_batch = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            inference_result = message.value
                            await self._evaluate_and_execute(inference_result)
                            self.stats['decisions_processed'] += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing inference result: {e}")
                            self.stats['errors'] += 1
                
            except Exception as e:
                logger.error(f"Error in decision processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _evaluate_and_execute(self, inference_result: Dict[str, Any]):
        """Evaluate policies and execute decisions."""
        try:
            # Evaluate policies
            decisions = self.policy_engine.evaluate_policies(inference_result)
            
            # Execute decisions
            for decision in decisions:
                await self.prevention_engine.execute_decision(decision)
                
                # Update statistics
                if "block_ip" in decision.action:
                    self.stats['blocks_executed'] += 1
                if "alert" in decision.action:
                    self.stats['alerts_sent'] += 1
                
                # Send decision to Kafka for logging
                await self._send_decision_log(decision)
            
            # If no decisions were made, log as normal traffic
            if not decisions:
                logger.debug(f"Normal traffic from {inference_result.get('src_ip', 'unknown')}")
        
        except Exception as e:
            logger.error(f"Error evaluating and executing decisions: {e}")
            self.stats['errors'] += 1
    
    async def _send_decision_log(self, decision: Decision):
        """Send decision log to Kafka."""
        try:
            if self.kafka_producer:
                decision_data = {
                    'timestamp': decision.timestamp,
                    'src_ip': decision.src_ip,
                    'dst_ip': decision.dst_ip,
                    'policy_name': decision.policy_name,
                    'action': decision.action,
                    'reason': decision.reason,
                    'severity': decision.severity,
                    'risk_score': decision.risk_score,
                    'auto_block': decision.auto_block,
                    'block_duration': decision.block_duration,
                    'requires_approval': decision.requires_approval
                }
                
                future = self.kafka_producer.send(
                    'decision-logs',
                    key=decision.src_ip,
                    value=decision_data
                )
                
                try:
                    future.get(timeout=1)
                except KafkaError as e:
                    logger.error(f"Failed to send decision log to Kafka: {e}")
        
        except Exception as e:
            logger.error(f"Error sending decision log: {e}")
    
    async def _cleanup_task(self):
        """Periodic cleanup task."""
        while self.running:
            try:
                await self.prevention_engine.cleanup_expired_blocks()
                await asyncio.sleep(60)  # Run every minute
            
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(60)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get decision engine statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'decisions_processed': self.stats['decisions_processed'],
            'blocks_executed': self.stats['blocks_executed'],
            'alerts_sent': self.stats['alerts_sent'],
            'errors': self.stats['errors'],
            'decisions_per_second': self.stats['decisions_processed'] / uptime if uptime > 0 else 0,
            'blocked_ips_count': len(self.prevention_engine.get_blocked_ips()),
            'policies_count': len(self.policy_engine.policies)
        }
    
    def add_policy(self, policy: Policy):
        """Add a new policy to the engine."""
        self.policy_engine.add_policy(policy)
    
    def remove_policy(self, policy_name: str):
        """Remove a policy from the engine."""
        self.policy_engine.remove_policy(policy_name)
    
    def get_policies(self) -> Dict[str, Policy]:
        """Get all policies."""
        return self.policy_engine.policies.copy()
    
    def get_blocked_ips(self) -> Dict[str, BlockedIP]:
        """Get currently blocked IPs."""
        return self.prevention_engine.get_blocked_ips()
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return self.prevention_engine.is_ip_blocked(ip)
