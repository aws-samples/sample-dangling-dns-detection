"""
Amazon Route 53 CNAME record discovery module.

This module provides functionality to discover all CNAME records
across all Amazon Route 53 hosted zones in the AWS account.

Validates: Requirements 1.1, 1.2, 1.3
"""

import logging
from typing import Iterator, List, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from src.models import CnameRecord

logger = logging.getLogger(__name__)

__all__ = ["Route53Discovery"]


class Route53Discovery:
    """Discovers CNAME records from Route 53 hosted zones.
    
    This class handles pagination for both hosted zones and record sets,
    extracting all CNAME records with their associated metadata.
    """
    
    def __init__(self, client: Optional[BaseClient] = None):
        """Initialize the discovery service.
        
        Args:
            client: Optional boto3 Route 53 client. If not provided,
                   a new client will be created.
        """
        self._client = client or boto3.client('route53')
    
    def discover_cname_records(self) -> List[CnameRecord]:
        """Discover all CNAME records across all hosted zones.
        
        Iterates through all hosted zones in the account and extracts
        all CNAME records from each zone.
        
        Returns:
            List of CnameRecord objects representing all CNAME records found.
            
        Raises:
            ClientError: If there's an AWS API error during discovery.
        """
        return list(self._iterate_cname_records())
    
    def _iterate_cname_records(self) -> Iterator[CnameRecord]:
        """Iterate through all CNAME records across all hosted zones.
        
        Yields:
            CnameRecord objects for each CNAME record found.
        """
        for zone in self._iterate_hosted_zones():
            zone_id = zone['Id'].replace('/hostedzone/', '')
            zone_name = zone['Name'].rstrip('.')
            
            logger.debug(f"Scanning hosted zone: {zone_name} ({zone_id})")
            
            for record in self._iterate_zone_records(zone_id, zone_name):
                yield record
    
    def _iterate_hosted_zones(self) -> Iterator[dict]:
        """Iterate through all hosted zones with pagination.
        
        Yields:
            Dict representing each hosted zone from the API response.
        """
        paginator = self._client.get_paginator('list_hosted_zones')
        
        for page in paginator.paginate():
            for zone in page.get('HostedZones', []):
                yield zone
    
    def _iterate_zone_records(
        self,
        zone_id: str,
        zone_name: str
    ) -> Iterator[CnameRecord]:
        """Iterate through CNAME records in a specific hosted zone.
        
        Args:
            zone_id: The hosted zone ID (without /hostedzone/ prefix)
            zone_name: The hosted zone name (without trailing dot)
            
        Yields:
            CnameRecord objects for each CNAME record in the zone.
        """
        paginator = self._client.get_paginator('list_resource_record_sets')
        
        for page in paginator.paginate(HostedZoneId=zone_id):
            for record_set in page.get('ResourceRecordSets', []):
                if record_set.get('Type') != 'CNAME':
                    continue
                
                # Extract CNAME target from ResourceRecords
                resource_records = record_set.get('ResourceRecords', [])
                if not resource_records:
                    # Could be an alias record, skip
                    continue
                
                target = resource_records[0].get('Value', '')
                if not target:
                    continue
                
                # Strip trailing dot from record name
                record_name = record_set.get('Name', '').rstrip('.')
                
                yield CnameRecord(
                    zone_id=zone_id,
                    zone_name=zone_name,
                    record_name=record_name,
                    target=target.rstrip('.'),
                    ttl=record_set.get('TTL', 0)
                )
