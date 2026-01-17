from sqlmodel import SQLModel, Field
from typing import Optional
import uuid
from datetime import datetime

class DNSChangeLog(SQLModel, table=True):
    __tablename__ = "dns_change_log"

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True, index=True)

    domain: str = Field(index=True)
    action: str  # 'ADD', 'UPDATE', 'DELETE'
    record_type: str
    record_name: str
    record_value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None
    proxied: Optional[bool] = None

    # Optional: capture before/after as JSON string
    full_snapshot: str  # full DNS record as JSON string (after change)

    # Cryptographic fields
    snapshot_hash: str
    signature: str
    public_key: str

    # Metadata
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)