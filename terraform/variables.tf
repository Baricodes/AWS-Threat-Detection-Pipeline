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

variable "ses_alert_to_email" {
  description = "Recipient for threat-email-alerter. If empty, uses ses_identity_email."
  type        = string
  default     = ""
}
