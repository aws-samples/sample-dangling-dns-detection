"""
Unit tests for the PatternMatcher class.

Tests pattern matching for S3, CloudFront, and Elastic Beanstalk endpoints,
including edge cases like case sensitivity, regional variations, and invalid inputs.

Validates: Requirements 2.1, 2.2, 2.3, 2.5
"""

import pytest

from src.models import MatchResult, ResourceType
from src.pattern_matcher import PatternMatcher


class TestPatternMatcherS3:
    """Tests for S3 bucket pattern matching (Requirement 2.1)."""
    
    def setup_method(self):
        self.matcher = PatternMatcher()
    
    def test_s3_global_endpoint(self):
        """Test S3 global endpoint format: bucket.s3.amazonaws.com"""
        result = self.matcher.match("mybucket.s3.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "mybucket"
    
    def test_s3_regional_endpoint_new_format(self):
        """Test S3 regional endpoint: bucket.s3.region.amazonaws.com"""
        result = self.matcher.match("mybucket.s3.us-east-1.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "mybucket"
    
    def test_s3_regional_endpoint_legacy_format(self):
        """Test S3 legacy regional endpoint: bucket.s3-region.amazonaws.com"""
        result = self.matcher.match("mybucket.s3-us-west-2.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "mybucket"
    
    def test_s3_bucket_with_dots(self):
        """Test S3 bucket name containing dots."""
        result = self.matcher.match("my.bucket.name.s3.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "my.bucket.name"
    
    def test_s3_bucket_with_hyphens(self):
        """Test S3 bucket name containing hyphens."""
        result = self.matcher.match("my-bucket-name.s3.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "my-bucket-name"
    
    def test_s3_case_insensitive(self):
        """Test that S3 matching is case-insensitive (DNS is case-insensitive)."""
        result = self.matcher.match("MyBucket.S3.AMAZONAWS.COM")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "MyBucket"
    
    def test_s3_various_regions(self):
        """Test S3 endpoints with various AWS regions."""
        regions = ["us-east-1", "eu-west-1", "ap-southeast-1", "sa-east-1", "us-gov-west-1"]
        for region in regions:
            result = self.matcher.match(f"bucket.s3.{region}.amazonaws.com")
            assert result is not None, f"Failed for region {region}"
            assert result.resource_type == ResourceType.S3_BUCKET
            assert result.identifier == "bucket"


class TestPatternMatcherCloudFront:
    """Tests for CloudFront distribution pattern matching (Requirement 2.2)."""
    
    def setup_method(self):
        self.matcher = PatternMatcher()
    
    def test_cloudfront_distribution(self):
        """Test CloudFront distribution endpoint: id.cloudfront.net"""
        result = self.matcher.match("d1234abcdef.cloudfront.net")
        assert result is not None
        assert result.resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert result.identifier == "d1234abcdef"
    
    def test_cloudfront_case_insensitive(self):
        """Test that CloudFront matching is case-insensitive."""
        result = self.matcher.match("D1234ABCDEF.CLOUDFRONT.NET")
        assert result is not None
        assert result.resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert result.identifier == "D1234ABCDEF"
    
    def test_cloudfront_alphanumeric_id(self):
        """Test CloudFront with alphanumeric distribution ID."""
        result = self.matcher.match("abc123xyz789.cloudfront.net")
        assert result is not None
        assert result.resource_type == ResourceType.CLOUDFRONT_DISTRIBUTION
        assert result.identifier == "abc123xyz789"


class TestPatternMatcherElasticBeanstalk:
    """Tests for Elastic Beanstalk pattern matching (Requirement 2.3)."""
    
    def setup_method(self):
        self.matcher = PatternMatcher()
    
    def test_elasticbeanstalk_simple(self):
        """Test Elastic Beanstalk endpoint: env.elasticbeanstalk.com"""
        result = self.matcher.match("myapp-env.elasticbeanstalk.com")
        assert result is not None
        assert result.resource_type == ResourceType.ELASTICBEANSTALK_ENVIRONMENT
        assert result.identifier == "myapp-env"
    
    def test_elasticbeanstalk_regional(self):
        """Test Elastic Beanstalk regional endpoint: env.region.elasticbeanstalk.com"""
        result = self.matcher.match("myapp-env.us-east-1.elasticbeanstalk.com")
        assert result is not None
        assert result.resource_type == ResourceType.ELASTICBEANSTALK_ENVIRONMENT
        assert result.identifier == "myapp-env"
    
    def test_elasticbeanstalk_case_insensitive(self):
        """Test that Elastic Beanstalk matching is case-insensitive."""
        result = self.matcher.match("MyApp-Env.ELASTICBEANSTALK.COM")
        assert result is not None
        assert result.resource_type == ResourceType.ELASTICBEANSTALK_ENVIRONMENT
        assert result.identifier == "MyApp-Env"
    
    def test_elasticbeanstalk_various_regions(self):
        """Test Elastic Beanstalk endpoints with various AWS regions."""
        regions = ["us-east-1", "eu-west-1", "ap-northeast-1"]
        for region in regions:
            result = self.matcher.match(f"myenv.{region}.elasticbeanstalk.com")
            assert result is not None, f"Failed for region {region}"
            assert result.resource_type == ResourceType.ELASTICBEANSTALK_ENVIRONMENT
            assert result.identifier == "myenv"


class TestPatternMatcherOutOfScope:
    """Tests for out-of-scope targets (Requirement 2.5)."""
    
    def setup_method(self):
        self.matcher = PatternMatcher()
    
    def test_non_aws_domain(self):
        """Test that non-AWS domains return None."""
        result = self.matcher.match("www.example.com")
        assert result is None
    
    def test_external_service(self):
        """Test that external service domains return None."""
        result = self.matcher.match("api.github.com")
        assert result is None
    
    def test_partial_aws_domain(self):
        """Test that partial AWS domain matches return None."""
        result = self.matcher.match("amazonaws.com")
        assert result is None
    
    def test_similar_but_not_aws(self):
        """Test domains that look similar to AWS but aren't."""
        result = self.matcher.match("mybucket.s3.fakeamazonaws.com")
        assert result is None
    
    def test_empty_string(self):
        """Test that empty string returns None."""
        result = self.matcher.match("")
        assert result is None
    
    def test_none_input(self):
        """Test that None input returns None."""
        result = self.matcher.match(None)
        assert result is None
    
    def test_whitespace_only(self):
        """Test that whitespace-only string returns None."""
        result = self.matcher.match("   ")
        assert result is None


class TestPatternMatcherEdgeCases:
    """Tests for edge cases and special scenarios."""
    
    def setup_method(self):
        self.matcher = PatternMatcher()
    
    def test_trailing_dot_fqdn(self):
        """Test that trailing dot (FQDN format) is handled."""
        result = self.matcher.match("mybucket.s3.amazonaws.com.")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "mybucket"
    
    def test_multiple_trailing_dots(self):
        """Test handling of multiple trailing dots."""
        result = self.matcher.match("mybucket.s3.amazonaws.com...")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "mybucket"
    
    def test_mixed_case_throughout(self):
        """Test mixed case throughout the domain."""
        result = self.matcher.match("MyBucket.S3.Us-East-1.AmAzOnAwS.cOm")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "MyBucket"
    
    def test_numeric_bucket_name(self):
        """Test S3 bucket with numeric name."""
        result = self.matcher.match("123456789.s3.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == "123456789"
    
    def test_long_bucket_name(self):
        """Test S3 bucket with long name (up to 63 chars allowed)."""
        long_name = "a" * 63
        result = self.matcher.match(f"{long_name}.s3.amazonaws.com")
        assert result is not None
        assert result.resource_type == ResourceType.S3_BUCKET
        assert result.identifier == long_name
