#Terraform template for ALB Listener Encryption Compliance
#Plan output is used for alb_ssl_protocol.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#This ALB is valid because the Listener attached below is valid
resource "aws_lb" "validtest" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"

  enable_deletion_protection = true

}

#This Listener is valid because HTTPs is enabled, there is a valid certificate arn and the SSL Policy is an AWS
#reccomended policy
resource "aws_lb_listener" "valid_listener" {
  load_balancer_arn = aws_lb.validtest.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
  }
}

#This ALB is invalid because the Listener attached below is invalid
resource "aws_lb" "invalidtest" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"

  enable_deletion_protection = true

}

#This Listener is invalid becauase it is not using encryption or an aws reccomended SSL policy
resource "aws_lb_listener" "invalid_listener" {
  load_balancer_arn = aws_lb.invalidtest.arn
  port              = "80"
  protocol          = "HTTP"
  ssl_policy        = "ELBSecurityPolicy-2016"
  certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
  }
}

#This NLB is valid becuase this terraform template is not used to validate NLBs. This NLB is in the template to ensure
#the associated policy is not blocking NLBs from being built.
resource "aws_lb" "nlb_valid" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "network"

  enable_deletion_protection = true

}

#this listener is valid for the reasons above.
resource "aws_lb_listener" "nlb_listener" {
  load_balancer_arn = aws_lb.nlb_valid.arn
  port              = "80"
  protocol          = "HTTP"
  ssl_policy        = "ELBSecurityPolicy-2016"
  certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
  }
}