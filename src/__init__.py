# Dangling DNS Detection - AWS Config Custom Rule
# Detects CNAME records pointing to AWS resources no longer present in the account

from src.alerting import AlertingService
from src.discovery import Route53Discovery
from src.evaluator import ComplianceEvaluator, evaluate_record
from src.handler import ConfigRuleHandler, lambda_handler
from src.inventory import InventoryQuery
from src.metrics import MetricsPublisher
from src.models import (
    ComplianceStatus,
    CnameRecord,
    EvaluationResult,
    MatchResult,
    ResourceType,
)
from src.pattern_matcher import PatternMatcher

__all__ = [
    # Models and types
    "ResourceType",
    "ComplianceStatus",
    "CnameRecord",
    "EvaluationResult",
    "MatchResult",
    # Core services
    "PatternMatcher",
    "InventoryQuery",
    "ComplianceEvaluator",
    "evaluate_record",
    "Route53Discovery",
    "ConfigRuleHandler",
    "lambda_handler",
    "AlertingService",
    "MetricsPublisher",
]
