# Terraform template for CloudFront Logging
# Generated plan output used for rego test cloudfront_logging_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}
resource "aws_s3_bucket" "a" {
  bucket = "mybucket"
  acl    = "private"

  tags = {
    Name = "My bucket"
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
  acl    = "private"

  tags = {
    Name = "My bucket"
  }
}

locals {
  s3_origin_id   = "myS3Origin"
  s3_origin_id_2 = "myS3Origin"
}

#VALID: Logging is configured with logging_config
resource "aws_cloudfront_distribution" "valid" {
  origin {
    domain_name = aws_s3_bucket.a.bucket_regional_domain_name
    origin_id   = local.s3_origin_id_2

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "allow-all"
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

#INVALID: Logging is not configured with logging_config
resource "aws_cloudfront_distribution" "invalid" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "allow-all"
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
