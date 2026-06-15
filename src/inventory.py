"""
AWS Config inventory query module.

This module provides functionality to query AWS Config for existing
resources (S3 buckets, CloudFront distributions, and Elastic Beanstalk
environments) to determine if CNAME targets exist.

Validates: Requirements 3.1, 3.2, 3.3, 3.4
"""

import json
import logging
from typing import Dict, Optional, Set

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from src.models import ResourceType

logger = logging.getLogger(__name__)

__all__ = ["InventoryQuery"]


class InventoryQuery:
    """Queries AWS Config for resource inventory.
    
    Uses AWS Config advanced queries to retrieve lists of existing
    resources by type. Results are cached to avoid repeated API calls.
    """
    
    # AWS Config resource type mappings
    RESOURCE_TYPE_QUERIES: Dict[ResourceType, str] = {
        ResourceType.S3_BUCKET: "AWS::S3::Bucket",
        ResourceType.CLOUDFRONT_DISTRIBUTION: "AWS::CloudFront::Distribution",
        ResourceType.ELASTICBEANSTALK_ENVIRONMENT: "AWS::ElasticBeanstalk::Environment",
    }
    
    def __init__(self, client: Optional[BaseClient] = None):
        """Initialize the inventory query service.
        
        Args:
            client: Optional boto3 Config client. If not provided,
                   a new client will be created.
        """
        self._client = client or boto3.client('config')
        self._cache: Dict[ResourceType, Set[str]] = {}
    
    def resource_exists(self, resource_type: ResourceType, identifier: str) -> Optional[bool]:
        """Check if a resource exists in the Config inventory.
        
        Args:
            resource_type: The type of AWS resource to check.
            identifier: The resource identifier (bucket name, distribution ID, etc.)
            
        Returns:
            True if resource exists, False if not found, None if query failed.
        """
        try:
            resources = self._get_resources(resource_type)
            if resources is None:
                return None
            
            # Normalize identifier for comparison (lowercase for case-insensitive matching)
            normalized_id = identifier.lower()
            return normalized_id in resources
            
        except ClientError as e:
            logger.error(f"Error checking resource existence: {e}")
            return None
    
    def _get_resources(self, resource_type: ResourceType) -> Optional[Set[str]]:
        """Get all resources of a given type from Config inventory.
        
        Results are cached to avoid repeated API calls within the same
        Lambda invocation.
        
        Args:
            resource_type: The type of AWS resource to query.
            
        Returns:
            Set of resource identifiers (lowercase), or None if query failed.
        """
        if resource_type in self._cache:
            return self._cache[resource_type]
        
        try:
            resources = set()
            
            # Query primary resource type
            primary_type = self.RESOURCE_TYPE_QUERIES.get(resource_type)
            if primary_type:
                resources.update(self._query_resources(primary_type, resource_type))
            
            self._cache[resource_type] = resources
            return resources
            
        except ClientError as e:
            logger.error(f"Error querying Config inventory for {resource_type}: {e}")
            return None
    
    def _query_resources(self, config_resource_type: str, resource_type: ResourceType) -> Set[str]:
        """Run a Config advanced query for a specific resource type.
        
        Args:
            config_resource_type: AWS Config resource type string.
            resource_type: Our internal ResourceType enum.
            
        Returns:
            Set of resource identifiers (lowercase).
            
        Raises:
            ValueError: If config_resource_type is not in RESOURCE_TYPE_QUERIES values.
        """
        valid_types = set(self.RESOURCE_TYPE_QUERIES.values())
        if config_resource_type not in valid_types:
            raise ValueError(
                f"Invalid config resource type: '{config_resource_type}'. "
                f"Must be one of: {valid_types}"
            )
        
        resources = set()
        
        query = f"SELECT resourceId, resourceName, configuration WHERE resourceType = '{config_resource_type}'"
        
        next_token = None
        while True:
            kwargs = {'Expression': query}
            if next_token:
                kwargs['NextToken'] = next_token
            
            response = self._client.select_resource_config(**kwargs)
            
            for result in response.get('Results', []):
                identifier = self._extract_identifier(result, resource_type)
                if identifier:
                    resources.add(identifier.lower())
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        logger.debug(f"Found {len(resources)} {config_resource_type} resources")
        return resources
    
    def _extract_identifier(self, result: str, resource_type: ResourceType) -> Optional[str]:
        """Extract the resource identifier from a Config query result.
        
        Args:
            result: JSON string from Config query result.
            resource_type: The type of resource being queried.
            
        Returns:
            The resource identifier, or None if extraction failed.
        """
        try:
            data = json.loads(result)
            
            # For S3, use the bucket name (resourceName or resourceId)
            if resource_type == ResourceType.S3_BUCKET:
                return data.get('resourceName') or data.get('resourceId')
            
            # For CloudFront, extract distribution ID from resourceId
            if resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION:
                return data.get('resourceId')
            
            # For Elastic Beanstalk, use environment name
            if resource_type == ResourceType.ELASTICBEANSTALK_ENVIRONMENT:
                return data.get('resourceName') or data.get('resourceId')
            
            return data.get('resourceId')
            
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to extract identifier from result: {e}")
            return None
    
    def get_s3_buckets(self) -> Optional[Set[str]]:
        """Get all S3 bucket names from Config inventory.
        
        Returns:
            Set of bucket names (lowercase), or None if query failed.
        """
        return self._get_resources(ResourceType.S3_BUCKET)
    
    def get_cloudfront_distributions(self) -> Optional[Set[str]]:
        """Get all CloudFront distribution IDs from Config inventory.
        
        Returns:
            Set of distribution IDs (lowercase), or None if query failed.
        """
        return self._get_resources(ResourceType.CLOUDFRONT_DISTRIBUTION)
    
    def get_elasticbeanstalk_environments(self) -> Optional[Set[str]]:
        """Get all Elastic Beanstalk environment names from Config inventory.
        
        Returns:
            Set of environment names (lowercase), or None if query failed.
        """
        return self._get_resources(ResourceType.ELASTICBEANSTALK_ENVIRONMENT)
