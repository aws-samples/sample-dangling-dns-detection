"""
Amazon CloudWatch metrics publishing module.

This module provides functionality to publish evaluation metrics
to Amazon CloudWatch for monitoring and dashboarding.

Validates: Requirements 7.1, 7.2, 7.3, 7.5
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from src.models import ComplianceStatus, EvaluationResult, ResourceType

__all__ = ["MetricsPublisher"]

logger = logging.getLogger(__name__)


class MetricsPublisher:
    """Publishes evaluation metrics to CloudWatch.
    
    Tracks total evaluated, compliant, and non-compliant counts
    with breakdowns by resource type.
    """
    
    NAMESPACE = "DanglingDNS/Detection"
    
    def __init__(self, client: Optional[BaseClient] = None):
        """Initialize the metrics publisher.
        
        Args:
            client: Optional boto3 CloudWatch client.
        """
        self._client = client or boto3.client('cloudwatch')
    
    def publish_evaluation_metrics(
        self,
        results: List[EvaluationResult],
        evaluation_timestamp: Optional[datetime] = None,
    ) -> bool:
        """Publish evaluation metrics to CloudWatch.
        
        Publishes the following metrics:
        - TotalEvaluated: Total number of CNAME records evaluated
        - Compliant: Number of compliant records
        - NonCompliant: Number of non-compliant (dangling) records
        - NotApplicable: Number of out-of-scope records
        - InsufficientData: Number of records with query failures
        
        Each metric is also broken down by resource type dimension.
        
        Args:
            results: List of evaluation results.
            evaluation_timestamp: Optional timestamp to align metrics with the
                evaluation cycle. Falls back to datetime.now(timezone.utc).
            
        Returns:
            True if metrics published successfully, False otherwise.
        """
        metrics = self._calculate_metrics(results)
        timestamp = evaluation_timestamp or datetime.now(timezone.utc)
        metric_data = self._build_metric_data(metrics, timestamp)
        
        if not metric_data:
            logger.debug("No metrics to publish")
            return True
        
        try:
            # CloudWatch allows max 1000 metrics per request
            for i in range(0, len(metric_data), 1000):
                batch = metric_data[i:i + 1000]
                self._client.put_metric_data(
                    Namespace=self.NAMESPACE,
                    MetricData=batch
                )
            
            logger.info(f"Published {len(metric_data)} metrics to CloudWatch")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to publish metrics: {e}")
            return False
    
    def _calculate_metrics(self, results: List[EvaluationResult]) -> Dict[str, Any]:
        """Calculate metric values from evaluation results.
        
        Args:
            results: List of evaluation results.
            
        Returns:
            Dict with metric counts by status and resource type.
        """
        by_status: Counter = Counter(r.compliance_status for r in results)
        by_resource_type: Dict[ResourceType, Counter] = defaultdict(Counter)

        for result in results:
            if result.resource_type:
                by_resource_type[result.resource_type][result.compliance_status] += 1

        return {
            'total': len(results),
            'by_status': by_status,
            'by_resource_type': by_resource_type,
        }
    
    def _build_metric_data(self, metrics: Dict[str, Any], timestamp: datetime) -> List[Dict]:
        """Build CloudWatch metric data from calculated metrics.
        
        Args:
            metrics: Dict with calculated metric values.
            timestamp: Timestamp to use for all metric data points.
            
        Returns:
            List of CloudWatch metric data dicts.
        """
        metric_data = []
        
        # Total evaluated (aggregate)
        metric_data.append({
            'MetricName': 'TotalEvaluated',
            'Value': metrics['total'],
            'Unit': 'Count',
            'Timestamp': timestamp
        })
        
        # Status-based metrics (aggregate)
        status_metric_names = {
            ComplianceStatus.COMPLIANT: 'Compliant',
            ComplianceStatus.NON_COMPLIANT: 'NonCompliant',
            ComplianceStatus.NOT_APPLICABLE: 'NotApplicable',
            ComplianceStatus.INSUFFICIENT_DATA: 'InsufficientData'
        }
        
        for status, metric_name in status_metric_names.items():
            count = metrics['by_status'].get(status, 0)
            metric_data.append({
                'MetricName': metric_name,
                'Value': count,
                'Unit': 'Count',
                'Timestamp': timestamp
            })
        
        # Resource type breakdown
        for resource_type in ResourceType:
            type_metrics = metrics['by_resource_type'].get(resource_type, {})
            
            # Total for this resource type
            type_total = sum(type_metrics.values())
            if type_total > 0:
                metric_data.append({
                    'MetricName': 'TotalEvaluated',
                    'Value': type_total,
                    'Unit': 'Count',
                    'Timestamp': timestamp,
                    'Dimensions': [
                        {'Name': 'ResourceType', 'Value': resource_type.value}
                    ]
                })
            
            # Status breakdown for this resource type
            for status, metric_name in status_metric_names.items():
                count = type_metrics.get(status, 0)
                if count > 0:
                    metric_data.append({
                        'MetricName': metric_name,
                        'Value': count,
                        'Unit': 'Count',
                        'Timestamp': timestamp,
                        'Dimensions': [
                            {'Name': 'ResourceType', 'Value': resource_type.value}
                        ]
                    })
        
        return metric_data
    
    def publish_execution_metrics(
        self,
        duration_ms: float,
        zones_scanned: int,
        records_found: int,
        errors: int = 0
    ) -> bool:
        """Publish Lambda execution metrics.
        
        Args:
            duration_ms: Execution duration in milliseconds.
            zones_scanned: Number of hosted zones scanned.
            records_found: Number of CNAME records found.
            errors: Number of errors encountered.
            
        Returns:
            True if metrics published successfully, False otherwise.
        """
        timestamp = datetime.now(timezone.utc)
        
        metric_data = [
            {
                'MetricName': 'ExecutionDuration',
                'Value': duration_ms,
                'Unit': 'Milliseconds',
                'Timestamp': timestamp
            },
            {
                'MetricName': 'ZonesScanned',
                'Value': zones_scanned,
                'Unit': 'Count',
                'Timestamp': timestamp
            },
            {
                'MetricName': 'RecordsFound',
                'Value': records_found,
                'Unit': 'Count',
                'Timestamp': timestamp
            },
            {
                'MetricName': 'Errors',
                'Value': errors,
                'Unit': 'Count',
                'Timestamp': timestamp
            }
        ]
        
        try:
            self._client.put_metric_data(
                Namespace=self.NAMESPACE,
                MetricData=metric_data
            )
            logger.debug("Published execution metrics")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to publish execution metrics: {e}")
            return False
