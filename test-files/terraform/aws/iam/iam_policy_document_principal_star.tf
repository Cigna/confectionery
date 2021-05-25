# Terraform template for IAM Policy Document Principal Star
# Generated plan output used for rego test iam_policy_document_principal_star.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/credentials"
  profile                 = "saml"
}

#VALID: Principal is set to "*" but has a limiting condition
data "aws_iam_policy_document" "valid_condition" {

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
    ]

    condition {
      test     = "StringEquals"
      variable = "SNS:Protocol"

      values = [
        "email"
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

  }
}

#VALID: Principal is not set to "*"
data "aws_iam_policy_document" "valid_principal" {

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
    ]

    condition {
      test     = "StringEquals"
      variable = "sns:protocol"

      values = [
        "email"
      ]
    }

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

  }
}


#INVALID: Prinicpal is set to "*" with no limiting condition
data "aws_iam_policy_document" "invalid" {

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
    ]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

  }
}