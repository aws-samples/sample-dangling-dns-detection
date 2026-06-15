"""
AWS Lambda handler for Dangling DNS Detection.

This module provides the main entry point for the AWS Config custom rule
that detects dangling CNAME records pointing to deleted AWS resources.

Validates: Requirements 2.1, 2.2, 2.3, 4.1, 4.2, 7.1, 7.2, 7.3, 8.1, 8.2,
           13.1, 13.2, 24.1, 24.2, 24.3, 25.1, 25.2
"""

import json
import logging
import os
import random
import time
from collections import Counter
from functools import partial
from typing import Any, Callable, Dict, List, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from src.alerting import AlertingService
from src.discovery import Route53Discovery
from src.evaluator import ComplianceEvaluator
from src.metrics import MetricsPublisher
from src.models import ComplianceStatus, EvaluationResult

__all__ = ["ConfigRuleHandler", "lambda_handler"]

# Configure logging
logger = logging.getLogger()
_log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logger.setLevel(getattr(logging, _log_level, logging.INFO))

# Maximum annotation length for AWS Config evaluations
_MAX_ANNOTATION_LENGTH = 256


class ConfigRuleHandler:
    """Handles AWS Config rule invocations for dangling DNS detection.

    Orchestrates the discovery, evaluation, alerting, and metrics
    components to detect and report dangling CNAME records.
    """

    # Retry configuration
    MAX_RETRIES = 3
    BASE_DELAY_MS = 100
    MAX_DELAY_MS = 5000

    def __init__(
        self,
        config_client: Optional[BaseClient] = None,
        sns_topic_arn: Optional[str] = None,
        rng: Optional[random.Random] = None,
    ):
        """Initialize the handler.

        Args:
            config_client: Optional boto3 Config client.
            sns_topic_arn: Optional SNS topic ARN for notifications.
            rng: Optional random.Random instance for deterministic jitter testing.
                 Defaults to random.Random() in production.
        """
        self._config = config_client or boto3.client('config')
        self._sns_topic_arn = sns_topic_arn or os.environ.get('SNS_TOPIC_ARN')
        self._rng = rng or random.Random()  # nosec B311 - retry jitter only, not cryptographic

        # Eager initialization — always used
        self._discovery = Route53Discovery()
        self._evaluator = ComplianceEvaluator()

        # Lazy initialization — only used on success path
        self.__alerting: Optional[AlertingService] = None
        self.__metrics: Optional[MetricsPublisher] = None

    @property
    def _alerting_service(self) -> AlertingService:
        """Lazily initialize AlertingService on first access."""
        if self.__alerting is None:
            self.__alerting = AlertingService(sns_topic_arn=self._sns_topic_arn)
        return self.__alerting

    @property
    def _metrics_publisher(self) -> MetricsPublisher:
        """Lazily initialize MetricsPublisher on first access."""
        if self.__metrics is None:
            self.__metrics = MetricsPublisher()
        return self.__metrics

    def handle(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Handle AWS Config rule invocation.

        Args:
            event: AWS Config invocation event.
            context: Lambda context object.

        Returns:
            Response dict with execution summary.
        """
        start_time = time.time()
        correlation_id = context.aws_request_id if context else 'local'

        logger.info(json.dumps({
            "message": "Starting dangling DNS detection",
            "correlation_id": correlation_id,
        }))

        try:
            # Parse the Config event
            invoking_event = json.loads(event.get('invokingEvent', '{}'))
            result_token = event.get('resultToken')

            message_type = invoking_event.get('messageType', '')
            logger.info(json.dumps({
                "message": "Invocation type",
                "type": message_type,
                "correlation_id": correlation_id,
            }))

            # Discover all CNAME records
            records = self._discover_with_retry()
            logger.info(json.dumps({
                "message": "Discovery complete",
                "records_found": len(records),
                "correlation_id": correlation_id,
            }))

            # Evaluate records for compliance
            results = self._evaluate_with_isolation(records, correlation_id)

            # Report results to AWS Config
            if result_token:
                self._report_to_config(results, result_token)

            # Process alerts for non-compliant records
            alert_summary = self._alerting_service.process_results(results)

            # Publish metrics
            self._metrics_publisher.publish_evaluation_metrics(results)

            # Calculate execution time
            duration_ms = (time.time() - start_time) * 1000
            self._metrics_publisher.publish_execution_metrics(
                duration_ms=duration_ms,
                zones_scanned=len(set(r.record.zone_id for r in results)),
                records_found=len(records),
                errors=0,
            )

            summary = self._build_summary(results, alert_summary, duration_ms)
            logger.info(json.dumps({
                "message": "Completed",
                "summary": summary,
                "correlation_id": correlation_id,
            }))

            return summary

        except Exception as e:
            # Logged at warning because the exception is re-raised for the
            # caller to handle; logging at error would duplicate the signal.
            logger.warning(
                json.dumps({
                    "message": "Handler failed",
                    "error": type(e).__name__,
                    "correlation_id": correlation_id,
                }),
                exc_info=True,
            )

            duration_ms = (time.time() - start_time) * 1000
            self._metrics_publisher.publish_execution_metrics(
                duration_ms=duration_ms,
                zones_scanned=0,
                records_found=0,
                errors=1,
            )

            raise

    def _discover_with_retry(self) -> List:
        """Discover CNAME records with retry logic.

        Returns:
            List of CnameRecord objects.
        """
        return self._retry_with_backoff(
            lambda: self._discovery.discover_cname_records(),
            "CNAME discovery",
        )

    def _evaluate_with_isolation(
        self,
        records: List,
        correlation_id: str = "unknown",
    ) -> List[EvaluationResult]:
        """Evaluate records with error isolation.

        If evaluation fails for a single record, continue processing
        the remaining records. Error annotations are sanitized to avoid
        leaking internal details.

        Args:
            records: List of CnameRecord objects.
            correlation_id: Correlation ID for structured logging.

        Returns:
            List of EvaluationResult objects.
        """
        results = []

        for record in records:
            try:
                result = self._evaluator.evaluate_record(record)
                results.append(result)
            except Exception as e:
                # Log full details server-side for debugging
                logger.error(
                    json.dumps({
                        "message": "Failed to evaluate record",
                        "record_name": record.record_name,
                        "error": type(e).__name__,
                        "error_detail": str(e),
                        "correlation_id": correlation_id,
                    }),
                    exc_info=True,
                )
                # Sanitize: expose only the exception type, not the message
                annotation = f"Evaluation failed: {type(e).__name__}"
                results.append(EvaluationResult(
                    record=record,
                    resource_type=None,
                    compliance_status=ComplianceStatus.INSUFFICIENT_DATA,
                    annotation=annotation[:_MAX_ANNOTATION_LENGTH],
                ))

        return results

    def _report_to_config(
        self, results: List[EvaluationResult], result_token: str
    ) -> None:
        """Report evaluation results to AWS Config.

        Args:
            results: List of evaluation results.
            result_token: AWS Config result token.
        """
        evaluations = []

        for result in results:
            evaluation = {
                'ComplianceResourceType': 'AWS::Route53::RecordSet',
                'ComplianceResourceId': (
                    f"{result.record.zone_id}/{result.record.record_name}"
                ),
                'ComplianceType': result.compliance_status.value,
                'Annotation': result.annotation[:_MAX_ANNOTATION_LENGTH],
                'OrderingTimestamp': time.time(),
            }
            evaluations.append(evaluation)

        # Config allows max 100 evaluations per request
        for i in range(0, len(evaluations), 100):
            batch = evaluations[i:i + 100]
            self._retry_with_backoff(
                partial(
                    self._config.put_evaluations,
                    Evaluations=batch,
                    ResultToken=result_token,
                ),
                "Config put_evaluations",
            )

    def _retry_with_backoff(self, operation: Callable, operation_name: str) -> Any:
        """Run an operation with exponential backoff and jitter.

        Args:
            operation: Callable to execute.
            operation_name: Name for logging.

        Returns:
            Result of the operation.

        Raises:
            Exception: If all retries are exhausted.
        """
        last_exception = None

        for attempt in range(self.MAX_RETRIES):
            try:
                return operation()
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')

                # Don't retry on non-retryable errors
                if error_code in ['AccessDeniedException', 'ValidationException']:
                    raise

                last_exception = e

                if attempt < self.MAX_RETRIES - 1:
                    delay = self._calculate_backoff_delay(attempt)
                    logger.warning(
                        json.dumps({
                            "message": f"{operation_name} failed",
                            "attempt": attempt + 1,
                            "retry_delay_ms": delay,
                            "error": type(e).__name__,
                        })
                    )
                    time.sleep(delay / 1000)

        logger.error(json.dumps({
            "message": f"{operation_name} failed after {self.MAX_RETRIES} attempts",
        }))
        raise last_exception

    def _calculate_backoff_delay(self, attempt: int) -> int:
        """Calculate exponential backoff delay with jitter.

        Args:
            attempt: Current attempt number (0-indexed).

        Returns:
            Delay in milliseconds.
        """
        # Exponential backoff: base * 2^attempt
        delay = self.BASE_DELAY_MS * (2 ** attempt)

        # Add jitter (0-50% of delay)
        jitter = self._rng.randint(0, delay // 2)
        delay += jitter

        # Cap at max delay
        return min(delay, self.MAX_DELAY_MS)

    def _build_summary(
        self,
        results: List[EvaluationResult],
        alert_summary: Dict,
        duration_ms: float,
    ) -> Dict[str, Any]:
        """Build execution summary using single-pass Counter.

        Args:
            results: List of evaluation results.
            alert_summary: Summary from alerting service.
            duration_ms: Execution duration in milliseconds.

        Returns:
            Summary dict.
        """
        counts = Counter(r.compliance_status for r in results)

        return {
            'statusCode': 200,
            'totalRecords': len(results),
            'compliant': counts.get(ComplianceStatus.COMPLIANT, 0),
            'nonCompliant': counts.get(ComplianceStatus.NON_COMPLIANT, 0),
            'notApplicable': counts.get(ComplianceStatus.NOT_APPLICABLE, 0),
            'insufficientData': counts.get(ComplianceStatus.INSUFFICIENT_DATA, 0),
            'findingsCreated': alert_summary.get('findings_created', 0),
            'notificationsSent': alert_summary.get('notifications_sent', 0),
            'durationMs': round(duration_ms, 2),
        }


# Lambda handler entry point
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda entry point.

    Args:
        event: AWS Config invocation event.
        context: Lambda context object.

    Returns:
        Execution summary dict.
    """
    handler = ConfigRuleHandler()
    return handler.handle(event, context)
