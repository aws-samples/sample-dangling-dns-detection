"""
Pattern matching component for AWS resource endpoint identification.

This module provides the PatternMatcher class that identifies AWS resource types
from CNAME target DNS names using regex pattern matching.

Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5
"""

import re
from typing import List, Optional, Pattern

from src.models import MatchResult, ResourceType

__all__ = ["PatternMatcher"]


class PatternMatcher:
    """Matches CNAME targets against known AWS resource endpoint patterns.
    
    This class identifies AWS resource types from CNAME target DNS names
    and extracts the resource identifier (bucket name, distribution ID, etc.).
    
    DNS names are case-insensitive, so all matching is performed in lowercase.
    """
    
    # S3 bucket endpoint patterns
    # Formats:
    #   - bucket.s3.amazonaws.com (legacy/global)
    #   - bucket.s3.region.amazonaws.com (newer format)
    #   - bucket.s3-region.amazonaws.com (legacy regional format)
    S3_PATTERNS: List[Pattern[str]] = [
        re.compile(r'^(.+)\.s3\.amazonaws\.com$', re.IGNORECASE),
        re.compile(r'^(.+)\.s3-([a-z0-9-]+)\.amazonaws\.com$', re.IGNORECASE),
        re.compile(r'^(.+)\.s3\.([a-z0-9-]+)\.amazonaws\.com$', re.IGNORECASE),
    ]
    
    # CloudFront distribution endpoint patterns
    # Format: distributionid.cloudfront.net
    CLOUDFRONT_PATTERNS: List[Pattern[str]] = [
        re.compile(r'^([a-z0-9]+)\.cloudfront\.net$', re.IGNORECASE),
    ]
    
    # Elastic Beanstalk environment endpoint patterns
    # Formats:
    #   - environment.elasticbeanstalk.com
    #   - environment.region.elasticbeanstalk.com
    # Note: Regional pattern must come first to avoid greedy matching
    ELASTICBEANSTALK_PATTERNS: List[Pattern[str]] = [
        re.compile(r'^(.+)\.([a-z0-9-]+)\.elasticbeanstalk\.com$', re.IGNORECASE),
        re.compile(r'^(.+)\.elasticbeanstalk\.com$', re.IGNORECASE),
    ]
    
    
    def match(self, target: str) -> Optional[MatchResult]:
        """
        Match target against all patterns and extract resource identifier.
        
        Attempts to match the given CNAME target against known AWS resource
        endpoint patterns. If a match is found, returns a MatchResult with
        the resource type and extracted resource identifier.
        
        Args:
            target: CNAME target DNS name (e.g., 'mybucket.s3.amazonaws.com')
            
        Returns:
            MatchResult if matched, or None if the target doesn't match
            any known AWS pattern.
            
        Examples:
            >>> matcher = PatternMatcher()
            >>> matcher.match('mybucket.s3.amazonaws.com')
            MatchResult(resource_type=ResourceType.S3_BUCKET, identifier='mybucket')
            >>> matcher.match('d1234abcd.cloudfront.net')
            MatchResult(resource_type=ResourceType.CLOUDFRONT_DISTRIBUTION, identifier='d1234abcd')
            >>> matcher.match('www.example.com')
        """
        if not target or not isinstance(target, str):
            return None
        
        # Strip trailing dot if present (FQDN format)
        target = target.rstrip('.')
        
        if not target:
            return None
        
        # Try S3 patterns
        result = self._match_patterns(target, self.S3_PATTERNS, ResourceType.S3_BUCKET)
        if result:
            return result
        
        # Try CloudFront patterns
        result = self._match_patterns(target, self.CLOUDFRONT_PATTERNS, ResourceType.CLOUDFRONT_DISTRIBUTION)
        if result:
            return result
        
        # Try Elastic Beanstalk patterns
        result = self._match_patterns(target, self.ELASTICBEANSTALK_PATTERNS, ResourceType.ELASTICBEANSTALK_ENVIRONMENT)
        if result:
            return result
        
        # No match found - out of scope
        return None
    
    def _match_patterns(
        self,
        target: str,
        patterns: List[Pattern[str]],
        resource_type: ResourceType
    ) -> Optional[MatchResult]:
        """
        Try to match target against a list of patterns.
        
        Args:
            target: CNAME target DNS name
            patterns: List of compiled regex patterns to try
            resource_type: ResourceType to return if matched
            
        Returns:
            MatchResult if matched, None otherwise
        """
        for pattern in patterns:
            match = pattern.match(target)
            if match:
                # First capture group is always the resource identifier
                resource_identifier = match.group(1)
                return MatchResult(resource_type, resource_identifier)
        return None
