# models.py

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, BigInteger
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ActivationKeyCreate(BaseModel):
    # Potential fields if you want user-provided info. For now, we leave it empty.
    pass


class ActivationKeyDB(Base):
    __tablename__ = "activation_keys"

    id = Column(Integer, primary_key=True, index=True)
    # We store the *full* token; if we re-encode the token, we update this field.
    full_token = Column(String, unique=True, nullable=False)

    # For reference or indexing, we can store created_at, expires_at, etc.
    # But the real authority is in the token itself (we validate every time).
    created_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)

    # (Optional) If you want a quick DB check. You can store agent_deployed.
    # However, since your question emphasizes storing it in the token,
    # we might keep the DB in sync or rely fully on the token.
    agent_deployed = Column(Integer, default=0)
