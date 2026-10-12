import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON for SIEM and audit ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry.update(record.extra_data)

        return json.dumps(log_entry)


def setup_logger(name: str = "agent_firewall", level: str = "INFO") -> logging.Logger:
    """Configures and returns a structured JSON logger instance.

    Args:
        name: Logger name, defaults to 'agent_firewall'.
        level: Logging level string (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR').

    Returns:
        Configured logging.Logger instance.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger


class AuditLogger:
    """Dedicated logger for security events, token budgets, and traffic interception audits."""

    def __init__(self, name: str = "agent_firewall.audit"):
        self.logger = setup_logger(name)

    def log_event(
        self,
        event_type: str,
        severity: str,
        agent_id: str,
        details: Dict[str, Any],
        error: Optional[str] = None
    ) -> None:
        """Logs a structured security audit event."""
        extra_data = {
            "audit_event": event_type,
            "severity": severity,
            "agent_id": agent_id,
            "details": details,
        }
        if error:
            extra_data["error"] = error

        record = self.logger.makeRecord(
            self.logger.name,
            logging.INFO if severity.upper() in ["INFO", "LOW"] else logging.WARNING,
            "(audit)",
            0,
            f"Security Audit Event: {event_type} for agent {agent_id}",
            (),
            None
        )
        record.extra_data = extra_data
        self.logger.handle(record)
