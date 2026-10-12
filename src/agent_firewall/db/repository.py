from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator, List, Optional, Dict

from sqlmodel import Session, select

from agent_firewall.db.database import get_engine
from agent_firewall.db.models import AuditLog, TokenUsage, SecurityBlock

logger = logging.getLogger(__name__)


class AuditRepository:
    """Repository for managing audit logs, token usage, and security blocks in SQLite WAL."""

    def __init__(self) -> None:
        self.engine = get_engine()

    @contextmanager
    def _get_session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions with automatic commit/rollback."""
        session = Session(self.engine)
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}", exc_info=True)
            raise
        finally:
            session.close()

    def log_request(
        self,
        request_id: str,
        provider: str,
        model: str,
        prompt: str,
        redacted_prompt: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Records an incoming AI request."""
        with self._get_session() as session:
            audit_log = AuditLog(
                request_id=request_id,
                timestamp=datetime.utcnow(),
                provider=provider,
                model=model,
                prompt=prompt,
                redacted_prompt=redacted_prompt,
                metadata_json=json.dumps(metadata) if metadata else None,
            )
            session.add(audit_log)
            session.refresh(audit_log)
            return audit_log

    def log_response(
        self,
        request_id: str,
        response: str,
        redacted_response: str,
        status_code: int,
        latency_ms: float,
    ) -> Optional[AuditLog]:
        """Updates an existing audit log with the corresponding AI response."""
        with self._get_session() as session:
            statement = select(AuditLog).where(AuditLog.request_id == request_id)
            audit_log = session.exec(statement).first()
            if audit_log:
                audit_log.response = response
                audit_log.redacted_response = redacted_response
                audit_log.status_code = status_code
                audit_log.latency_ms = latency_ms
                session.add(audit_log)
                session.refresh(audit_log)
                return audit_log
            logger.warning(f"Attempted to log response for non-existent request_id: {request_id}")
            return None

    def log_token_usage(
        self,
        request_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        cost_usd: float,
    ) -> TokenUsage:
        """Records token consumption and calculated cost for a request."""
        with self._get_session() as session:
            usage = TokenUsage(
                request_id=request_id,
                timestamp=datetime.utcnow(),
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cost_usd=cost_usd,
            )
            session.add(usage)
            session.refresh(usage)
            return usage

    def log_security_block(
        self,
        request_id: str,
        block_type: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityBlock:
        """Records a security interception or policy violation."""
        with self._get_session() as session:
            block = SecurityBlock(
                request_id=request_id,
                timestamp=datetime.utcnow(),
                block_type=block_type,
                reason=reason,
                details_json=json.dumps(details) if details else None,
            )
            session.add(block)
            session.refresh(block)
            return block

    def get_audit_log(self, request_id: str) -> Optional[AuditLog]:
        """Retrieves a single audit log by its unique request ID."""
        with self._get_session() as session:
            statement = select(AuditLog).where(AuditLog.request_id == request_id)
            return session.exec(statement).first()

    def list_audit_logs(self, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        """Retrieves a paginated list of audit logs ordered by most recent first."""
        with self._get_session() as session:
            statement = select(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
            return list(session.exec(statement).all())

    def get_token_usage_summary(self) -> Dict[str, Any]:
        """Aggregates total tokens consumed and total cost incurred."""
        with self._get_session() as session:
            statement = select(TokenUsage)
            usages = session.exec(statement).all()
            
            total_prompt = sum(u.prompt_tokens for u in usages)
            total_completion = sum(u.completion_tokens for u in usages)
            total_tokens = sum(u.total_tokens for u in usages)
            total_cost = sum(u.cost_usd for u in usages)
            
            return {
                "total_prompt_tokens": total_prompt,
                "total_completion_tokens": total_completion,
                "total_tokens": total_tokens,
                "total_cost_usd": total_cost,
                "request_count": len(usages),
            }

    def list_security_blocks(self, limit: int = 100, offset: int = 0) -> List[SecurityBlock]:
        """Retrieves a paginated list of security blocks ordered by most recent first."""
        with self._get_session() as session:
            statement = select(SecurityBlock).order_by(SecurityBlock.timestamp.desc()).offset(offset).limit(limit)
            return list(session.exec(statement).all())
