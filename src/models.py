"""
Data models and enums for the Dangling DNS Detection solution.

This module defines the core data structures used throughout the solution
for representing CNAME records, resource types, compliance statuses,
evaluation results, and pattern match results.

Validates: Requirements 4.3, 5.2, 9.1, 9.2, 10.1, 12.1, 12.2, 13.1, 14.1-14.5, 23.1, 23.2
"""

from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple, Optional

__all__ = [
    "ResourceType",
    "ComplianceStatus",
    "CnameRecord",
    "EvaluationResult",
    "MatchResult",
]


class ResourceType(Enum):
    """Types of AWS resources that can be CNAME targets.

    These represent the AWS services whose endpoints can be identified
    from CNAME record targets and checked against Config inventory.
    """
    S3_BUCKET = "S3"
    CLOUDFRONT_DISTRIBUTION = "CloudFront"
    ELASTICBEANSTALK_ENVIRONMENT = "ElasticBeanstalk"


class ComplianceStatus(Enum):
    """AWS Config compliance status values.

    These values match the expected compliance status strings
    used by AWS Config for reporting evaluation results.
    """
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"       # For out-of-scope CNAMEs
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"  # When inventory query fails


class MatchResult(NamedTuple):
    """Result of a pattern match operation.

    Attributes:
        resource_type: The type of AWS resource matched.
        identifier: The extracted resource identifier from the CNAME target.
    """
    resource_type: ResourceType
    identifier: str


@dataclass(slots=True, frozen=True)
class CnameRecord:
    """Represents a CNAME record from Route 53.

    Attributes:
        zone_id: Hosted zone ID (e.g., 'Z1234567890ABC')
        zone_name: Hosted zone name (e.g., 'example.com')
        record_name: Full record name (e.g., 'app.example.com')
        target: CNAME target (e.g., 'mybucket.s3.amazonaws.com')
        ttl: Record TTL in seconds
    """
    zone_id: str
    zone_name: str
    record_name: str
    target: str
    ttl: int

    def __post_init__(self) -> None:
        if not isinstance(self.zone_id, str) or not self.zone_id:
            raise ValueError("zone_id must be a non-empty string")
        if not isinstance(self.record_name, str) or not self.record_name:
            raise ValueError("record_name must be a non-empty string")
        if not isinstance(self.target, str) or not self.target:
            raise ValueError("target must be a non-empty string")
        if not isinstance(self.ttl, int) or isinstance(self.ttl, bool) or self.ttl < 0:
            raise ValueError("ttl must be a non-negative integer")


@dataclass(slots=True, frozen=True)
class EvaluationResult:
    """Result of evaluating a single CNAME record.

    Attributes:
        record: The CNAME record that was evaluated
        resource_type: The type of AWS resource (None if out of scope)
        compliance_status: The compliance status determination
        annotation: Explanation of the compliance status
        resource_identifier: Extracted resource name/ID from the target
    """
    record: CnameRecord
    resource_type: Optional[ResourceType]
    compliance_status: ComplianceStatus
    annotation: str
    resource_identifier: Optional[str] = None
