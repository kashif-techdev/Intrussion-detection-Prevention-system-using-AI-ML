"""
Model serving service for the AI-powered IDS/IPS system.
Provides real-time inference using trained ML models.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
import numpy as np
import pandas as pd
from dataclasses import dataclass
import joblib
import onnxruntime as ort
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class InferenceResult:
    """Result of model inference."""
    timestamp: float
    src_ip: str
    dst_ip: str
    model_name: str
    model_version: str
    prediction: Union[int, str]
    confidence: float
    anomaly_score: Optional[float] = None
    feature_importance: Optional[Dict[str, float]] = None
    processing_time: float = 0.0


class ModelRegistry:
    """Model registry for managing multiple ML models."""
    
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.models: Dict[str, Dict[str, Any]] = {}
        self.model_versions: Dict[str, str] = {}
    
    def load_model(self, model_name: str, model_type: str = "sklearn") -> bool:
        """Load a model from disk.
        
        Args:
            model_name: Name of the model to load
            model_type: Type of model (sklearn, onnx, pytorch)
            
        Returns:
            True if model loaded successfully
        """
        try:
            model_file = self.model_path / f"{model_name}.{model_type}"
            
            if model_type == "sklearn":
                model = joblib.load(model_file)
                self.models[model_name] = {
                    'model': model,
                    'type': model_type,
                    'loaded_at': time.time()
                }
            elif model_type == "onnx":
                session = ort.InferenceSession(str(model_file))
                self.models[model_name] = {
                    'model': session,
                    'type': model_type,
                    'loaded_at': time.time()
                }
            else:
                logger.error(f"Unsupported model type: {model_type}")
                return False
            
            # Load model metadata
            metadata_file = self.model_path / f"{model_name}_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    self.model_versions[model_name] = metadata.get('version', 'unknown')
            
            logger.info(f"Loaded model: {model_name} (type: {model_type})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            return False
    
    def get_model(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get a loaded model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Model dictionary or None if not found
        """
        return self.models.get(model_name)
    
    def list_models(self) -> List[str]:
        """List all loaded models."""
        return list(self.models.keys())
    
    def unload_model(self, model_name: str):
        """Unload a model from memory."""
        if model_name in self.models:
            del self.models[model_name]
            if model_name in self.model_versions:
                del self.model_versions[model_name]
            logger.info(f"Unloaded model: {model_name}")


class FeatureProcessor:
    """Feature processor for preparing data for model inference."""
    
    def __init__(self):
        self.feature_columns = [
            'duration', 'packet_count', 'byte_count', 'packets_per_second',
            'bytes_per_second', 'avg_packet_size', 'std_packet_size',
            'min_packet_size', 'max_packet_size', 'time_of_day', 'day_of_week',
            'entropy', 'unique_dst_ports', 'unique_dst_ips', 'recent_flows',
            'recent_bytes', 'recent_packets'
        ]
        
        # TCP flags
        self.tcp_flag_columns = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
        
        # HTTP features
        self.http_columns = [
            'http_request_count', 'http_response_count', 'http_avg_uri_length',
            'http_unique_user_agents', 'http_methods_GET', 'http_methods_POST',
            'http_methods_PUT', 'http_methods_DELETE'
        ]
        
        # DNS features
        self.dns_columns = [
            'dns_query_count', 'dns_response_count', 'dns_nxdomain_ratio',
            'dns_avg_domain_length', 'dns_unique_domains'
        ]
    
    def process_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Process features for model inference.
        
        Args:
            features: Raw feature dictionary
            
        Returns:
            Processed feature array
        """
        try:
            # Initialize feature vector
            feature_vector = []
            
            # Basic flow features
            for col in self.feature_columns:
                value = features.get(col, 0)
                if isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            # TCP flags
            tcp_flags = features.get('tcp_flags', {})
            for col in self.tcp_flag_columns:
                feature_vector.append(float(tcp_flags.get(col, 0)))
            
            # HTTP features
            http_features = features.get('http_features', {})
            for col in self.http_columns:
                if col.startswith('http_methods_'):
                    method = col.split('_')[-1]
                    feature_vector.append(float(http_features.get('methods', {}).get(method, 0)))
                else:
                    feature_vector.append(float(http_features.get(col.replace('http_', ''), 0)))
            
            # DNS features
            dns_features = features.get('dns_features', {})
            for col in self.dns_columns:
                feature_vector.append(float(dns_features.get(col.replace('dns_', ''), 0)))
            
            return np.array(feature_vector, dtype=np.float32)
        
        except Exception as e:
            logger.error(f"Error processing features: {e}")
            return np.zeros(len(self.feature_columns) + len(self.tcp_flag_columns) + 
                          len(self.http_columns) + len(self.dns_columns), dtype=np.float32)


class ModelServer:
    """Main model serving service."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.model_registry = ModelRegistry(self.config.model.model_path)
        self.feature_processor = FeatureProcessor()
        
        # Kafka components
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        
        # Model configurations
        self.model_configs = {
            'anomaly_detector': {
                'model_name': 'isolation_forest',
                'model_type': 'sklearn',
                'threshold': 0.8
            },
            'classifier': {
                'model_name': 'random_forest',
                'model_type': 'sklearn',
                'threshold': 0.7
            },
            'sequence_model': {
                'model_name': 'lstm_anomaly',
                'model_type': 'onnx',
                'threshold': 0.6
            }
        }
        
        # Statistics
        self.stats = {
            'inferences_processed': 0,
            'anomalies_detected': 0,
            'attacks_classified': 0,
            'errors': 0,
            'start_time': None,
            'model_load_times': {}
        }
        
        self.running = False
    
    async def start(self):
        """Start the model serving service."""
        try:
            logger.info("Starting model serving service...")
            
            # Load models
            await self._load_models()
            
            # Initialize Kafka consumer
            self.kafka_consumer = KafkaConsumer(
                self.config.kafka.topics['features'],
                bootstrap_servers=self.config.kafka.bootstrap_servers,
                group_id=f"{self.config.kafka.consumer_group}_inference",
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
            asyncio.create_task(self._process_features())
            
            logger.info("Model serving service started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start model serving service: {e}")
            raise
    
    async def stop(self):
        """Stop the model serving service."""
        try:
            self.running = False
            
            if self.kafka_consumer:
                self.kafka_consumer.close()
            
            if self.kafka_producer:
                self.kafka_producer.close()
            
            logger.info("Model serving service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping model serving service: {e}")
    
    async def _load_models(self):
        """Load all configured models."""
        for model_type, config in self.model_configs.items():
            model_name = config['model_name']
            model_file_type = config['model_type']
            
            start_time = time.time()
            success = self.model_registry.load_model(model_name, model_file_type)
            load_time = time.time() - start_time
            
            self.stats['model_load_times'][model_name] = load_time
            
            if success:
                logger.info(f"Loaded {model_type}: {model_name} in {load_time:.2f}s")
            else:
                logger.warning(f"Failed to load {model_type}: {model_name}")
    
    async def _process_features(self):
        """Main processing loop for feature inference."""
        while self.running:
            try:
                # Poll for messages
                message_batch = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            features = message.value
                            await self._run_inference(features)
                            self.stats['inferences_processed'] += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing features: {e}")
                            self.stats['errors'] += 1
                
            except Exception as e:
                logger.error(f"Error in inference processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _run_inference(self, features: Dict[str, Any]):
        """Run inference on features using all available models."""
        try:
            start_time = time.time()
            
            # Process features
            feature_vector = self.feature_processor.process_features(features)
            
            # Run anomaly detection
            anomaly_result = await self._run_anomaly_detection(feature_vector, features)
            
            # Run classification
            classification_result = await self._run_classification(feature_vector, features)
            
            # Run sequence analysis
            sequence_result = await self._run_sequence_analysis(feature_vector, features)
            
            # Combine results
            combined_result = self._combine_results(
                anomaly_result, classification_result, sequence_result, features
            )
            
            # Send results to decision engine
            await self._send_results(combined_result)
            
            processing_time = time.time() - start_time
            
            # Update statistics
            if combined_result.get('anomaly_score', 0) > 0.8:
                self.stats['anomalies_detected'] += 1
            
            if combined_result.get('prediction') == 'attack':
                self.stats['attacks_classified'] += 1
            
            logger.debug(f"Inference completed in {processing_time:.3f}s")
        
        except Exception as e:
            logger.error(f"Error running inference: {e}")
            self.stats['errors'] += 1
    
    async def _run_anomaly_detection(self, feature_vector: np.ndarray, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run anomaly detection model."""
        try:
            model_info = self.model_registry.get_model('isolation_forest')
            if not model_info:
                return {'anomaly_score': 0.0, 'is_anomaly': False}
            
            model = model_info['model']
            
            if model_info['type'] == 'sklearn':
                # Isolation Forest returns negative anomaly scores
                anomaly_score = -model.decision_function([feature_vector])[0]
                # Normalize to 0-1 range
                anomaly_score = max(0, min(1, (anomaly_score + 0.5) / 1.0))
            else:
                # For other model types, implement accordingly
                anomaly_score = 0.0
            
            threshold = self.model_configs['anomaly_detector']['threshold']
            is_anomaly = anomaly_score > threshold
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': is_anomaly,
                'model_name': 'isolation_forest',
                'threshold': threshold
            }
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return {'anomaly_score': 0.0, 'is_anomaly': False}
    
    async def _run_classification(self, feature_vector: np.ndarray, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run classification model."""
        try:
            model_info = self.model_registry.get_model('random_forest')
            if not model_info:
                return {'prediction': 'normal', 'confidence': 0.0}
            
            model = model_info['model']
            
            if model_info['type'] == 'sklearn':
                # Get prediction and probability
                prediction = model.predict([feature_vector])[0]
                probabilities = model.predict_proba([feature_vector])[0]
                confidence = float(max(probabilities))
                
                # Map prediction to label
                if hasattr(model, 'classes_'):
                    if prediction == 1 or (len(model.classes_) > 1 and model.classes_[1] == 'attack'):
                        prediction_label = 'attack'
                    else:
                        prediction_label = 'normal'
                else:
                    prediction_label = 'normal' if prediction == 0 else 'attack'
            else:
                prediction_label = 'normal'
                confidence = 0.0
            
            threshold = self.model_configs['classifier']['threshold']
            is_attack = prediction_label == 'attack' and confidence > threshold
            
            return {
                'prediction': prediction_label,
                'confidence': float(confidence),
                'is_attack': is_attack,
                'model_name': 'random_forest',
                'threshold': threshold
            }
        
        except Exception as e:
            logger.error(f"Error in classification: {e}")
            return {'prediction': 'normal', 'confidence': 0.0}
    
    async def _run_sequence_analysis(self, feature_vector: np.ndarray, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run sequence analysis model."""
        try:
            model_info = self.model_registry.get_model('lstm_anomaly')
            if not model_info:
                return {'sequence_anomaly_score': 0.0, 'is_sequence_anomaly': False}
            
            model = model_info['model']
            
            if model_info['type'] == 'onnx':
                # Prepare input for ONNX model
                input_name = model.get_inputs()[0].name
                input_data = feature_vector.reshape(1, 1, -1).astype(np.float32)
                
                # Run inference
                result = model.run(None, {input_name: input_data})
                sequence_anomaly_score = float(result[0][0][0])
            else:
                sequence_anomaly_score = 0.0
            
            threshold = self.model_configs['sequence_model']['threshold']
            is_sequence_anomaly = sequence_anomaly_score > threshold
            
            return {
                'sequence_anomaly_score': sequence_anomaly_score,
                'is_sequence_anomaly': is_sequence_anomaly,
                'model_name': 'lstm_anomaly',
                'threshold': threshold
            }
        
        except Exception as e:
            logger.error(f"Error in sequence analysis: {e}")
            return {'sequence_anomaly_score': 0.0, 'is_sequence_anomaly': False}
    
    def _combine_results(self, anomaly_result: Dict, classification_result: Dict, 
                        sequence_result: Dict, features: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from all models."""
        try:
            # Extract key information
            src_ip = features.get('src_ip', 'unknown')
            dst_ip = features.get('dst_ip', 'unknown')
            timestamp = features.get('timestamp', time.time())
            
            # Combine anomaly scores
            anomaly_score = anomaly_result.get('anomaly_score', 0.0)
            sequence_anomaly_score = sequence_result.get('sequence_anomaly_score', 0.0)
            combined_anomaly_score = max(anomaly_score, sequence_anomaly_score)
            
            # Determine final prediction
            is_anomaly = anomaly_result.get('is_anomaly', False) or sequence_result.get('is_sequence_anomaly', False)
            is_attack = classification_result.get('is_attack', False)
            
            # Calculate overall risk score
            risk_score = 0.0
            if is_attack:
                risk_score = max(risk_score, classification_result.get('confidence', 0.0))
            if is_anomaly:
                risk_score = max(risk_score, combined_anomaly_score)
            
            # Determine final decision
            if is_attack and risk_score > 0.8:
                final_prediction = 'attack'
                severity = 'high'
            elif is_anomaly and risk_score > 0.6:
                final_prediction = 'suspicious'
                severity = 'medium'
            else:
                final_prediction = 'normal'
                severity = 'low'
            
            return {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'prediction': final_prediction,
                'severity': severity,
                'risk_score': risk_score,
                'anomaly_score': anomaly_score,
                'sequence_anomaly_score': sequence_anomaly_score,
                'classification_confidence': classification_result.get('confidence', 0.0),
                'is_anomaly': is_anomaly,
                'is_attack': is_attack,
                'model_results': {
                    'anomaly': anomaly_result,
                    'classification': classification_result,
                    'sequence': sequence_result
                },
                'processing_time': time.time() - timestamp
            }
        
        except Exception as e:
            logger.error(f"Error combining results: {e}")
            return {
                'timestamp': time.time(),
                'src_ip': features.get('src_ip', 'unknown'),
                'dst_ip': features.get('dst_ip', 'unknown'),
                'prediction': 'normal',
                'severity': 'low',
                'risk_score': 0.0,
                'error': str(e)
            }
    
    async def _send_results(self, results: Dict[str, Any]):
        """Send inference results to Kafka."""
        try:
            if self.kafka_producer:
                future = self.kafka_producer.send(
                    self.config.kafka.topics['decisions'],
                    key=results['src_ip'],
                    value=results
                )
                
                try:
                    future.get(timeout=1)
                except KafkaError as e:
                    logger.error(f"Failed to send results to Kafka: {e}")
                    self.stats['errors'] += 1
        
        except Exception as e:
            logger.error(f"Error sending results: {e}")
            self.stats['errors'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model serving statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'inferences_processed': self.stats['inferences_processed'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'attacks_classified': self.stats['attacks_classified'],
            'errors': self.stats['errors'],
            'inferences_per_second': self.stats['inferences_processed'] / uptime if uptime > 0 else 0,
            'loaded_models': self.model_registry.list_models(),
            'model_load_times': self.stats['model_load_times']
        }
