from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
from datetime import datetime, timezone

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Status(str, Enum):
    FAIL = "FAIL"
    PASS = "PASS"
    SKIP = "SKIP"


class Framework(str, Enum):
    CIS_AWS_1_4 = "CIS_AWS_1.4"
    AWS_WAF     = "AWS_WAF_SECURITY"


class Finding(BaseModel):
    # Identidad del control
    control_id:   str            = Field(..., description="Ej: CIS-S3-2.1")
    control_name: str            = Field(..., description="Nombre legible del control")
    framework:    Framework
    service:      str            = Field(..., description="s3 | iam | ec2 | rds | guardduty | cloudwatch")

    # Resultado
    status:       Status
    severity:     Severity
    resource_id:  str            = Field(..., description="ARN o ID del recurso evaluado")
    region:       str

    # Detalle
    message:      str            = Field(..., description="Descripción del hallazgo")
    remediation:  str            = Field(..., description="Pasos de remediación")
    evidence:     dict           = Field(default_factory=dict, description="Raw data de soporte")

    # Metadata
    timestamp:    datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    account_id:   Optional[str]  = None