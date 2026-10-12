import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class AuditLog(Base):
    """
    SQLAlchemy model representing an intercepted API request/response audit log,
    including security screening results and token consumption metrics.
    """
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    provider = Column(String(50), nullable=False, index=True)
    endpoint = Column(String(255), nullable=False)
    model = Column(String(100), nullable=False, index=True)
    request_payload = Column(Text, nullable=False)
    response_payload = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=False)
    tokens_prompt = Column(Integer, default=0, nullable=False)
    tokens_completion = Column(Integer, default=0, nullable=False)
    tokens_total = Column(Integer, default=0, nullable=False)
    cost_estimated = Column(Float, default=0.0, nullable=False)
    blocked = Column(Boolean, default=False, nullable=False, index=True)
    block_reason = Column(Text, nullable=True)
    secrets_redacted_count = Column(Integer, default=0, nullable=False)
    latency_ms = Column(Float, default=0.0, nullable=False)

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, provider='{self.provider}', model='{self.model}', blocked={self.blocked}, tokens={self.tokens_total})>"


class BudgetTracker(Base):
    """
    SQLAlchemy model tracking aggregate token and monetary consumption budgets
    per agent or globally over specific time windows.
    """
    __tablename__ = 'budget_tracker'

    id = Column(Integer, primary_key=True, autoincrement=True)
    period_key = Column(String(50), unique=True, nullable=False, index=True)
    total_tokens = Column(Integer, default=0, nullable=False)
    total_cost = Column(Float, default=0.0, nullable=False)
    budget_limit_tokens = Column(Integer, default=100000, nullable=False)
    budget_limit_cost = Column(Float, default=10.0, nullable=False)
    circuit_breaker_tripped = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<BudgetTracker(period='{self.period_key}', tokens={self.total_tokens}/{self.budget_limit_tokens}, tripped={self.circuit_breaker_tripped})>"


def init_db(db_url: str = "sqlite:///agent_firewall.db"):
    """
    Initializes the SQLite database with WAL mode enabled for concurrent performance.
    """
    engine = create_engine(db_url, connect_args={"timeout": 15})
    
    # Enable WAL mode explicitly for SQLite
    if "sqlite" in db_url:
        @engine.connect()
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory
