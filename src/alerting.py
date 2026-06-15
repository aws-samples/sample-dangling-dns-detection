"""
Alerting module for AWS Security Hub and Amazon SNS notifications.

This module provides functionality to create AWS Security Hub findings
and publish Amazon SNS notifications for detected dangling CNAME records.

Validates: Requirements 5.1, 5.2, 5.3, 5.4, 6.1, 6.2, 6.3
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from functools import cached_property
from typing import Dict, List, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from src.models import ComplianceStatus, EvaluationResult, ResourceType

__all__ = ["AlertingService"]

logger = logging.getLogger(__name__)


class AlertingService:
    """Manages Security Hub findings and SNS notifications.
    
    Handles creation and archival of Security Hub findings for
    dangling CNAME records, and publishes SNS notifications.
    """
    
    SEVERITY_LABEL = "HIGH"
    SEVERITY_NORMALIZED = 70  # HIGH severity (70-89)
    PRODUCT_NAME = "Dangling DNS Detection"
    COMPANY_NAME = "Custom"
    
    def __init__(
        self,
        securityhub_client: Optional[BaseClient] = None,
        sns_client: Optional[BaseClient] = None,
        sts_client: Optional[BaseClient] = None,
        sns_topic_arn: Optional[str] = None
    ):
        """Initialize the alerting service.
        
        Args:
            securityhub_client: Optional boto3 Security Hub client.
            sns_client: Optional boto3 SNS client.
            sts_client: Optional boto3 STS client for account ID.
            sns_topic_arn: Optional SNS topic ARN for notifications.
        """
        self._securityhub = securityhub_client or boto3.client('securityhub')
        self._sns = sns_client or boto3.client('sns')
        self._sts = sts_client or boto3.client('sts')
        self._sns_topic_arn = sns_topic_arn
    
    @cached_property
    def account_id(self) -> str:
        """Get the AWS account ID."""
        return self._sts.get_caller_identity()['Account']
    
    @cached_property
    def region(self) -> str:
        """Get the AWS region."""
        return self._securityhub.meta.region_name
    
    def create_security_hub_finding(self, result: EvaluationResult, timestamp: Optional[str] = None) -> Optional[str]:
        """Create a Security Hub finding for a non-compliant record.
        
        Args:
            result: The evaluation result for a non-compliant record.
            timestamp: Optional ISO format timestamp. Defaults to current UTC time.
            
        Returns:
            The finding ID if created successfully, None otherwise.
        """
        if result.resource_type is None:
            logger.warning("Cannot create finding for record without resource type")
            return None
        
        finding_id = str(uuid.uuid4())
        now = timestamp or datetime.now(timezone.utc).isoformat()
        
        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': finding_id,
            'ProductArn': f'arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default',
            'GeneratorId': 'dangling-dns-detection',
            'AwsAccountId': self.account_id,
            'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
            'CreatedAt': now,
            'UpdatedAt': now,
            'Severity': {
                'Label': self.SEVERITY_LABEL,
                'Normalized': self.SEVERITY_NORMALIZED
            },
            'Title': f'Dangling CNAME Record: {result.record.record_name}',
            'Description': (
                f"CNAME record '{result.record.record_name}' points to a non-existent "
                f"{result.resource_type.value} resource '{result.resource_identifier}'. "
                f"This creates a subdomain takeover vulnerability."
            ),
            'Remediation': {
                'Recommendation': {
                    'Text': (
                        'Delete the dangling CNAME record from Route 53, or recreate '
                        'the target AWS resource with the same name/identifier.'
                    ),
                    'Url': 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-deleting.html'
                }
            },
            'Resources': [
                {
                    'Type': 'AwsRoute53HostedZone',
                    'Id': f'arn:aws:route53:::hostedzone/{result.record.zone_id}',
                    'Region': self.region,
                    'Details': {
                        'Other': {
                            'RecordName': result.record.record_name,
                            'CnameTarget': result.record.target,
                            'TargetResourceType': result.resource_type.value,
                            'TargetResourceIdentifier': result.resource_identifier or ''
                        }
                    }
                }
            ],
            'RecordState': 'ACTIVE',
            'Workflow': {'Status': 'NEW'}
        }
        
        try:
            self._securityhub.batch_import_findings(Findings=[finding])
            logger.info(f"Created Security Hub finding: {finding_id}")
            return finding_id
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidAccessException':
                logger.warning("Security Hub is not enabled in this account/region")
            else:
                logger.error(f"Failed to create Security Hub finding: {e}")
            return None
    
    def archive_security_hub_finding(self, finding_id: str) -> bool:
        """Archive a Security Hub finding when the issue is resolved.
        
        Args:
            finding_id: The ID of the finding to archive.
            
        Returns:
            True if archived successfully, False otherwise.
        """
        try:
            self._securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': finding_id,
                        'ProductArn': f'arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default'
                    }
                ],
                Workflow={'Status': 'RESOLVED'},
                Note={
                    'Text': 'Dangling CNAME record has been remediated',
                    'UpdatedBy': 'dangling-dns-detection'
                }
            )
            logger.info(f"Archived Security Hub finding: {finding_id}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to archive Security Hub finding: {e}")
            return False
    
    def publish_sns_notification(self, result: EvaluationResult, timestamp: Optional[str] = None) -> bool:
        """Publish an SNS notification for a non-compliant record.
        
        Args:
            result: The evaluation result for a non-compliant record.
            timestamp: Optional ISO format timestamp. Defaults to current UTC time.
            
        Returns:
            True if published successfully, False otherwise.
        """
        if not self._sns_topic_arn:
            logger.debug("SNS topic ARN not configured, skipping notification")
            return False
        
        if result.resource_type is None:
            logger.warning("Cannot publish notification for record without resource type")
            return False
        
        message = self._build_sns_message(result, timestamp=timestamp)
        subject = f"Dangling CNAME Detected: {result.record.record_name}"
        
        try:
            self._sns.publish(
                TopicArn=self._sns_topic_arn,
                Subject=subject[:100],  # SNS subject limit
                Message=message
            )
            logger.info(f"Published SNS notification for {result.record.record_name}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to publish SNS notification: {e}")
            return False
    
    def _build_sns_message(self, result: EvaluationResult, timestamp: Optional[str] = None) -> str:
        """Build the SNS notification message.
        
        Args:
            result: The evaluation result.
            timestamp: Optional ISO format timestamp. Defaults to current UTC time.
            
        Returns:
            Formatted message string.
        """
        return json.dumps({
            'alertType': 'DanglingCNAME',
            'severity': self.SEVERITY_LABEL,
            'record': {
                'name': result.record.record_name,
                'target': result.record.target,
                'zoneId': result.record.zone_id,
                'zoneName': result.record.zone_name
            },
            'resource': {
                'type': result.resource_type.value if result.resource_type else None,
                'identifier': result.resource_identifier
            },
            'remediation': {
                'action': 'Delete the CNAME record or recreate the target resource',
                'documentation': 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-deleting.html'
            },
            'timestamp': timestamp or datetime.now(timezone.utc).isoformat()
        })
    
    def process_results(self, results: List[EvaluationResult]) -> Dict[str, int]:
        """Process evaluation results and send alerts for non-compliant records.
        
        Args:
            results: List of evaluation results.
            
        Returns:
            Summary dict with counts of findings and notifications created.
        """
        summary = {
            'findings_created': 0,
            'findings_failed': 0,
            'notifications_sent': 0,
            'notifications_failed': 0
        }
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        for result in results:
            if result.compliance_status != ComplianceStatus.NON_COMPLIANT:
                continue
            
            # Create Security Hub finding
            finding_id = self.create_security_hub_finding(result, timestamp=timestamp)
            if finding_id:
                summary['findings_created'] += 1
            else:
                summary['findings_failed'] += 1
            
            # Send SNS notification
            if self._sns_topic_arn:
                if self.publish_sns_notification(result, timestamp=timestamp):
                    summary['notifications_sent'] += 1
                else:
                    summary['notifications_failed'] += 1
        
        return summary
