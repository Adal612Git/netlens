"""
Persistencia SQLite con SQLAlchemy ORM para NetLens.

Modelos:
- Target(id, name, url)
- Probe(id, target_id FK, timestamp)
- Result(id, probe_id FK, ip, port, whois, geoip, tls, dns en JSON)

APIs:
- init_db(db_url): crea tablas
- get_session(db_url): devuelve una sesión de SQLAlchemy
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session


Base = declarative_base()


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)

    probes = relationship("Probe", back_populates="target", cascade="all, delete-orphan")


class Probe(Base):
    __tablename__ = "probes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    target = relationship("Target", back_populates="probes")
    results = relationship("Result", back_populates="probe", cascade="all, delete-orphan")


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    probe_id = Column(Integer, ForeignKey("probes.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    whois = Column(JSON, nullable=True)
    geoip = Column(JSON, nullable=True)
    tls = Column(JSON, nullable=True)
    dns = Column(JSON, nullable=True)

    probe = relationship("Probe", back_populates="results")


DEFAULT_DB_URL = "sqlite:///netlens.db"
# Mantener engines y sessionmakers por URL para evitar contaminación entre tests
_engines: dict[str, Engine] = {}
_sessionmakers: dict[str, sessionmaker] = {}


def _key(db_url: Optional[str]) -> str:
    return db_url or DEFAULT_DB_URL


def _get_engine(db_url: Optional[str] = None) -> Engine:
    url = _key(db_url)
    if url in _engines:
        return _engines[url]
    # Para SQLite y posibles usos en hilos (FastAPI/CLI)
    engine = create_engine(url, connect_args={"check_same_thread": False})
    _engines[url] = engine
    return engine


def init_db(db_url: Optional[str] = None) -> Engine:
    """Inicializa la base de datos creando las tablas si no existen."""
    engine = _get_engine(db_url)
    Base.metadata.create_all(engine)
    return engine


def get_session(db_url: Optional[str] = None) -> Session:
    """Devuelve una sesión SQLAlchemy vinculada al engine por defecto.

    Uso típico:
        session = get_session()
        try:
            ...
            session.commit()
        finally:
            session.close()
    """

    engine = _get_engine(db_url)
    key = _key(db_url)
    if key not in _sessionmakers:
        _sessionmakers[key] = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _sessionmakers[key]()


__all__ = [
    "Target",
    "Probe",
    "Result",
    "init_db",
    "get_session",
]
