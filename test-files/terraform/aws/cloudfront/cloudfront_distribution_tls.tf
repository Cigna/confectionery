# Terraform template for Cloudtrail Distribution Cipher version check: enforce TLSv1.2_* or higher
# _* above can currently be 2018 or 2019 -> TLSv1.2_2018 is a valid cipher
# Generated plan output used for rego test cloudtrail_distribution_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# Supplemental resource
resource "aws_s3_bucket" "test_bucket" {
  bucket = "mybucket"
  acl    = "private"

  tags = {
    Name = "My bucket"
  }
}

locals {
  s3_origin_id = "test_origin"
}

# VALID : TLSv1.2_2018 is an allowed ssl version
resource "aws_cloudfront_distribution" "valid" {
  origin {
    domain_name = aws_s3_bucket.test_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }
  enabled             = true

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
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }
  #This part matters, everything above the viewer_certificate block is not important
    viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.2_2019"
  }
  
}

# INVALID : TLSv1.1 is not an allowed ssl version
resource "aws_cloudfront_distribution" "invalid" {
  origin {
    domain_name = aws_s3_bucket.test_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }
  enabled             = true

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
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }
  #This part matters, everything above the viewer_certificate block is not important
    viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.1"
  }
  
}