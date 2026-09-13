"""Declarative base — every ORM model in the project inherits from this,
and Alembic's env.py points at `Base.metadata` for autogenerate.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
