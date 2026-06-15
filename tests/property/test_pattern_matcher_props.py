"""
Property-based tests for PatternMatcher.

Feature: code-quality-optimization, Properties 5-9: Pattern matching properties

Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5
"""

import pytest
from hypothesis import given, assume
from hypothesis import strategies as st

from src.models import MatchResult, ResourceType
from src.pattern_matcher import PatternMatcher

matcher = PatternMatcher()

# --- Strategies ---

# AWS endpoint substrings that indicate an AWS resource (case-insensitive)
AWS_MARKERS = [".s3.amazonaws.com", ".s3-", ".cloudfront.net", ".elasticbeanstalk.com"]

# Valid S3 bucket name characters: lowercase letters, digits, hyphens, dots
# Bucket names are 1-63 chars, must start/end with letter or digit
s3_bucket_names = st.from_regex(r"[a-z0-9][a-z0-9.\-]{0,61}[a-z0-9]", fullmatch=True).filter(
    lambda s: ".." not in s and len(s) <= 63
)

# Valid AWS region strings
aws_regions = st.sampled_from([
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1",
    "sa-east-1", "ca-central-1", "us-gov-west-1",
])

# CloudFront distribution IDs: alphanumeric, typically 13-14 chars
cloudfront_ids = st.from_regex(r"[a-z0-9]{6,14}", fullmatch=True)



@pytest.mark.property
class TestNonAwsDomainsProduceNoMatch:
    """Property 5: Non-AWS domains produce no match.

    For any string that does not contain the substrings .s3.amazonaws.com,
    .s3-, .cloudfront.net, or .elasticbeanstalk.com (case-insensitive),
    PatternMatcher.match() SHALL return None.

    **Validates: Requirements 18.1**
    """

    @given(target=st.text())
    def test_non_aws_domains_return_none(self, target: str) -> None:
        """Strings without AWS endpoint markers never match."""
        lowered = target.lower()
        assume(not any(marker in lowered for marker in AWS_MARKERS))
        assert matcher.match(target) is None


@pytest.mark.property
class TestValidS3EndpointsProduceCorrectMatch:
    """Property 6: Valid S3 endpoints produce correct match.

    For any valid bucket name and region string, constructing
    {bucket}.s3.{region}.amazonaws.com and calling match() SHALL return
    a MatchResult with ResourceType.S3_BUCKET and the correct bucket name.

    **Validates: Requirements 18.2**
    """

    @given(bucket=s3_bucket_names, region=aws_regions)
    def test_s3_regional_endpoint_matches(self, bucket: str, region: str) -> None:
        """Valid S3 regional endpoints always produce S3_BUCKET match."""
        endpoint = f"{bucket}.s3.{region}.amazonaws.com"
        result = matcher.match(endpoint)
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == bucket


@pytest.mark.property
class TestValidCloudFrontEndpointsProduceCorrectMatch:
    """Property 7: Valid CloudFront endpoints produce correct match.

    For any valid alphanumeric distribution ID, constructing
    {id}.cloudfront.net and calling match() SHALL return a MatchResult
    with ResourceType.CLOUDFRONT_DISTRIBUTION and the correct ID.

    **Validates: Requirements 18.3**
    """

    @given(dist_id=cloudfront_ids)
    def test_cloudfront_endpoint_matches(self, dist_id: str) -> None:
        """Valid CloudFront endpoints always produce CLOUDFRONT_DISTRIBUTION match."""
        endpoint = f"{dist_id}.cloudfront.net"
        result = matcher.match(endpoint)
        assert result is not None
        assert result.resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert result.identifier == dist_id


@pytest.mark.property
class TestPatternMatchingIsIdempotent:
    """Property 8: Pattern matching is idempotent.

    For any string input, calling match(x) twice SHALL produce identical results.

    **Validates: Requirements 18.4**
    """

    @given(target=st.text())
    def test_match_is_idempotent(self, target: str) -> None:
        """Matching the same input twice always produces the same result."""
        assert matcher.match(target) == matcher.match(target)


@pytest.mark.property
class TestTrailingDotsDoNotAffectMatchResult:
    """Property 9: Trailing dots do not affect match result.

    For any string input x, match(x) SHALL equal match(x + '.').

    **Validates: Requirements 18.5**
    """

    @given(target=st.text())
    def test_trailing_dot_invariant(self, target: str) -> None:
        """Appending a trailing dot does not change the match result."""
        assert matcher.match(target) == matcher.match(target + ".")
