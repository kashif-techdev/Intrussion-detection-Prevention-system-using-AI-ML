"""
Logging configuration for the AI-powered IDS/IPS system.
Provides structured logging with different levels and handlers.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in log_entry:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class SecurityFormatter(logging.Formatter):
    """Specialized formatter for security events."""
    
    def format(self, record):
        """Format security log record."""
        return f"[SECURITY] {record.levelname}: {record.getMessage()}"


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    enable_console: bool = True,
    enable_json: bool = False,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
):
    """Setup logging configuration for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        enable_console: Enable console logging
        enable_json: Use JSON formatting
        max_file_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
    """
    # Create logs directory if it doesn't exist
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        
        if enable_json:
            console_formatter = JSONFormatter()
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        
        if enable_json:
            file_formatter = JSONFormatter()
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Security logger
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)
    
    if log_file:
        security_file = Path(log_file).parent / "security.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        security_handler.setFormatter(SecurityFormatter())
        security_logger.addHandler(security_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("kafka").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
    
    def log_attack_detected(self, attack_type: str, source_ip: str, target_ip: str, 
                           confidence: float, details: dict = None):
        """Log detected attack."""
        self.logger.warning(
            f"Attack detected: {attack_type} from {source_ip} to {target_ip} "
            f"(confidence: {confidence:.2f})",
            extra={
                "event_type": "attack_detected",
                "attack_type": attack_type,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "confidence": confidence,
                "details": details or {}
            }
        )
    
    def log_block_action(self, action: str, ip: str, reason: str, duration: int = None):
        """Log blocking action."""
        self.logger.info(
            f"Block action: {action} for IP {ip} - {reason}",
            extra={
                "event_type": "block_action",
                "action": action,
                "ip": ip,
                "reason": reason,
                "duration": duration
            }
        )
    
    def log_false_positive(self, alert_id: str, analyst: str, reason: str):
        """Log false positive feedback."""
        self.logger.info(
            f"False positive reported: {alert_id} by {analyst} - {reason}",
            extra={
                "event_type": "false_positive",
                "alert_id": alert_id,
                "analyst": analyst,
                "reason": reason
            }
        )
    
    def log_model_update(self, model_name: str, version: str, performance: dict):
        """Log model update."""
        self.logger.info(
            f"Model updated: {model_name} v{version}",
            extra={
                "event_type": "model_update",
                "model_name": model_name,
                "version": version,
                "performance": performance
            }
        )


# Global security logger instance
security_logger = SecurityLogger()
