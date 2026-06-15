"""
Compliance evaluation module for dangling CNAME detection.

This module provides the core logic for evaluating CNAME records
against AWS Config inventory to determine compliance status.

Validates: Requirements 4.1, 4.2, 4.3, 6.1, 6.2, 9.4, 10.2, 13.1
"""

import logging
from typing import List, Optional

from src.inventory import InventoryQuery
from src.models import CnameRecord, ComplianceStatus, EvaluationResult, ResourceType
from src.pattern_matcher import PatternMatcher

logger = logging.getLogger(__name__)

__all__ = ["ComplianceEvaluator", "evaluate_record"]


class ComplianceEvaluator:
    """Evaluates CNAME records for dangling DNS vulnerabilities.
    
    Integrates pattern matching and inventory queries to determine
    if CNAME records point to existing or deleted AWS resources.
    """
    
    def __init__(
        self,
        pattern_matcher: Optional[PatternMatcher] = None,
        inventory_query: Optional[InventoryQuery] = None
    ):
        """Initialize the compliance evaluator.
        
        Args:
            pattern_matcher: Optional PatternMatcher instance.
            inventory_query: Optional InventoryQuery instance.
        """
        self._pattern_matcher = pattern_matcher or PatternMatcher()
        self._inventory_query = inventory_query or InventoryQuery()
    
    def evaluate_records(self, records: List[CnameRecord]) -> List[EvaluationResult]:
        """Evaluate a list of CNAME records for compliance.
        
        Args:
            records: List of CNAME records to evaluate.
            
        Returns:
            List of EvaluationResult objects with compliance status.
        """
        return [self.evaluate_record(record) for record in records]
    
    def evaluate_record(self, record: CnameRecord) -> EvaluationResult:
        """Evaluate a single CNAME record for compliance.
        
        The evaluation logic:
        1. Match the CNAME target against AWS resource patterns
        2. If no match, mark as NOT_APPLICABLE (out of scope)
        3. If match, check if resource exists in Config inventory
        4. If exists, mark as COMPLIANT
        5. If not exists, mark as NON_COMPLIANT (dangling)
        6. If inventory query fails, mark as INSUFFICIENT_DATA
        
        Args:
            record: The CNAME record to evaluate.
            
        Returns:
            EvaluationResult with compliance status and annotation.
        """
        # Step 1: Pattern match the CNAME target
        match_result = self._pattern_matcher.match(record.target)
        
        if match_result is None:
            # Out of scope - not an AWS resource endpoint
            return EvaluationResult(
                record=record,
                resource_type=None,
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                annotation=f"CNAME target '{record.target}' is not an AWS resource endpoint",
                resource_identifier=None
            )
        
        resource_type = match_result.resource_type
        resource_identifier = match_result.identifier
        
        # Step 2: Check if resource exists in inventory
        exists = self._inventory_query.resource_exists(resource_type, resource_identifier)
        
        if exists is None:
            # Inventory query failed
            return EvaluationResult(
                record=record,
                resource_type=resource_type,
                compliance_status=ComplianceStatus.INSUFFICIENT_DATA,
                annotation=f"Unable to verify existence of {resource_type.value} resource '{resource_identifier}'",
                resource_identifier=resource_identifier
            )
        
        if exists:
            # Resource exists - compliant
            return EvaluationResult(
                record=record,
                resource_type=resource_type,
                compliance_status=ComplianceStatus.COMPLIANT,
                annotation=f"{resource_type.value} resource '{resource_identifier}' exists",
                resource_identifier=resource_identifier
            )
        
        # Resource does not exist - dangling CNAME detected
        return EvaluationResult(
            record=record,
            resource_type=resource_type,
            compliance_status=ComplianceStatus.NON_COMPLIANT,
            annotation=self._build_non_compliant_annotation(record, resource_type, resource_identifier),
            resource_identifier=resource_identifier
        )
    
    def _build_non_compliant_annotation(
        self,
        record: CnameRecord,
        resource_type: ResourceType,
        resource_identifier: str
    ) -> str:
        """Build a detailed annotation for non-compliant records.
        
        The annotation includes all information needed for remediation:
        - Record name
        - CNAME target
        - Resource type
        - Resource identifier
        
        Args:
            record: The non-compliant CNAME record.
            resource_type: The type of AWS resource.
            resource_identifier: The extracted resource identifier.
            
        Returns:
            Detailed annotation string.
        """
        return (
            f"DANGLING CNAME DETECTED: Record '{record.record_name}' "
            f"points to non-existent {resource_type.value} resource. "
            f"Target: '{record.target}', "
            f"Resource identifier: '{resource_identifier}'. "
            f"This record is vulnerable to subdomain takeover."
        )


_evaluator: Optional[ComplianceEvaluator] = None


def evaluate_record(record: CnameRecord) -> EvaluationResult:
    """Convenience function to evaluate a single CNAME record.

    Uses a lazily-initialized module-level singleton to avoid creating
    a new ComplianceEvaluator on every call.

    Args:
        record: The CNAME record to evaluate.

    Returns:
        EvaluationResult with compliance status.
    """
    global _evaluator
    if _evaluator is None:
        _evaluator = ComplianceEvaluator()
    return _evaluator.evaluate_record(record)
