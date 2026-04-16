variable "aws_region" {
  description = "AWS region for resources."
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID for this deployment."
  type        = string
}

variable "ses_identity_email" {
  description = "Email address to register as a verified SES identity (check inbox to complete verification)."
  type        = string
}
