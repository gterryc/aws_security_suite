from pydantic import BaseModel, Field
from typing import Any
from datetime import datetime, timezone

class CollectorOutput(BaseModel):
    service:      str            = Field(..., description="s3 | iam | ec2 | rds | guardduty | cloudwatch")
    account_id:   str
    region:       str
    collected_at: datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data:     dict[str, Any] = Field(default_factory=dict, description="Data cruda indexada por recurso")
    errors:       list[str]      = Field(default_factory=list,  description="Errores no fatales durante la recolección")