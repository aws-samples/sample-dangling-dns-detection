"""Pytest configuration and shared fixtures for Dangling DNS Detection tests."""

import pytest
from hypothesis import settings, Verbosity

# Configure hypothesis settings for property-based tests
settings.register_profile(
    "default",
    max_examples=100,
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "ci",
    max_examples=200,
    verbosity=Verbosity.verbose,
)

settings.register_profile(
    "debug",
    max_examples=10,
    verbosity=Verbosity.verbose,
)

settings.load_profile("default")


@pytest.fixture
def sample_cname_targets():
    """Sample CNAME targets for testing pattern matching."""
    return {
        "s3": [
            "mybucket.s3.amazonaws.com",
            "mybucket.s3.us-east-1.amazonaws.com",
            "mybucket.s3-us-west-2.amazonaws.com",
        ],
        "cloudfront": [
            "d1234abcd.cloudfront.net",
            "d111111abcdef8.cloudfront.net",
        ],
        "elasticbeanstalk": [
            "myapp.elasticbeanstalk.com",
            "myapp.us-east-1.elasticbeanstalk.com",
        ],
        "non_aws": [
            "example.com",
            "api.github.com",
            "cdn.example.org",
        ],
    }
